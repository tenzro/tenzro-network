//! AI Model inference types for Tenzro Network
//!
//! This module defines types for AI model registration, inference requests,
//! and provider management.

use crate::hardware::HardwareCapabilities;
use crate::meter::unit;
use crate::primitives::{Address, Hash, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// License tier for a model, governing whether it may be registered/loaded
/// without operator acknowledgement.
///
/// Enforced centrally in `ModelRegistry::register_model()` against the
/// registry's [`crate::model::AcceptancePolicy`]:
///
/// - `Permissive` (Apache-2.0, MIT, BSD-2/3): loaded by default, no friction.
/// - `Attribution` (CC-BY-4.0): loaded by default; the attribution string is
///   surfaced so operators stay compliant with the BY clause.
/// - `CommercialCustom`: bespoke commercial-OK licenses with non-standard
///   terms (DINOv3 License, SAM License, Gemma Terms). Requires the model's
///   `license_id` to be in the policy's accepted set.
/// - `NonCommercial` (CC-BY-NC, OpenRAIL-M, …): refused unless the policy has
///   `accept_non_commercial` set.
///
/// Tiers are ordered from least to most restrictive, so the tier of weights
/// under several licences is the greatest of theirs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LicenseTier {
    #[default]
    Permissive,
    Attribution,
    CommercialCustom,
    NonCommercial,
}

impl LicenseTier {
    /// Whether a model under this licence may be charged for or served to a
    /// paying caller. A non-commercial licence grants neither: such a model is
    /// served only free of charge, to callers who pay nothing.
    pub fn permits_paid_use(self) -> bool {
        !matches!(self, Self::NonCommercial)
    }
}

/// What a license's territorial restriction reaches.
///
/// The distinction decides *where* enforcement has to live, so it is a type
/// rather than a comment. A weights-only restriction is discharged by not
/// redistributing the weights — a registration-time concern. A restriction that
/// also covers **outputs** cannot be: serving an inference to an excluded
/// territory produces an output there, so every request has to be checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TerritorialScope {
    /// The grant limits distribution of the weights themselves. Enforced when
    /// the model is registered and served, not per request.
    #[default]
    Weights,
    /// The grant also limits the model's *outputs* — so a request served to an
    /// excluded territory is itself a breach, regardless of where the weights
    /// live. Forces a per-request check.
    ///
    /// MiniMax H3's §V.4 is this: "You may not use, reproduce, modify,
    /// distribute, or display the MiniMax H3 Works **or any of their Outputs or
    /// results** outside the Applicable Territory."
    WeightsAndOutputs,
}

/// A license's territorial grant, as data.
///
/// Attached to a **license id** rather than a model, because the restriction is
/// a property of the licence: every model under `minimax-h3-community` inherits
/// the same territory, and a new restricted licence is a table entry rather
/// than a code change.
///
/// Not every territorial licence needs a per-request gate. Llama's EU
/// restriction withholds rights from EU-*domiciled* companies but explicitly
/// exempts "end users of a product or service that incorporates" the model —
/// a test on who the operator is, not where each caller sits. Encode that as
/// [`TerritorialScope::Weights`]. Reach for `WeightsAndOutputs` only when the
/// licence covers outputs **and** grants no end-user carve-out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TerritorialGrant {
    /// ISO 3166-1 alpha-2 codes and bloc tokens (e.g. `EU`) the grant does NOT
    /// cover. Empty means unrestricted.
    ///
    /// Blocs are kept unexpanded here so the recorded value stays faithful to
    /// the licence text; [`Self::excludes`] expands them at match time. That
    /// also means a change in bloc membership is picked up by updating one
    /// table rather than every licence that names the bloc.
    pub excluded: Vec<String>,
    /// Whether the restriction reaches outputs, and so whether it has to be
    /// enforced per request.
    pub scope: TerritorialScope,
}

/// Members of a bloc token used in [`TerritorialGrant::excluded`].
///
/// Bloc membership drifts, and a licence naming a bloc is ambiguous about
/// whether it means membership at signing or membership now. This resolves to
/// **current** membership, which is the reading that keeps the operator inside
/// the grant as the bloc grows — the conservative direction for a restriction.
pub fn bloc_members(token: &str) -> Option<&'static [&'static str]> {
    match token.to_ascii_uppercase().as_str() {
        // EU-27 as of 2026. Deliberately spelled out rather than inferred from
        // a crate: this list is a compliance artefact and must be reviewable.
        "EU" => Some(&[
            "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IE",
            "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE",
        ]),
        // The EEA adds Iceland, Liechtenstein and Norway to the EU. Present
        // because some licences name the EEA rather than the EU.
        "EEA" => Some(&[
            "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IE",
            "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE", "IS",
            "LI", "NO",
        ]),
        _ => None,
    }
}

impl TerritorialGrant {
    /// Whether `country` (ISO 3166-1 alpha-2) is outside the grant.
    ///
    /// Case-insensitive, and expands bloc tokens. An empty `excluded` list is
    /// unrestricted, so this returns false — the common case for the licences
    /// that carry no territorial term at all.
    pub fn excludes(&self, country: &str) -> bool {
        let c = country.trim().to_ascii_uppercase();
        if c.is_empty() {
            return false;
        }
        self.excluded.iter().any(|token| {
            let t = token.trim().to_ascii_uppercase();
            if t == c {
                return true;
            }
            bloc_members(&t).is_some_and(|members| members.contains(&c.as_str()))
        })
    }

    /// Whether this grant has to be checked on every request.
    pub fn is_per_request(&self) -> bool {
        !self.excluded.is_empty() && self.scope == TerritorialScope::WeightsAndOutputs
    }

    /// Whether the grant restricts anything at all.
    pub fn is_restricted(&self) -> bool {
        !self.excluded.is_empty()
    }
}

/// How a request's territory was established.
///
/// Recorded on every decision because §V.5-style clauses ("reasonable and
/// proportionate technical and organizational safeguards") are **evidentiary**
/// standards: what converts an implementation from an assertion of reasonable
/// effort into proof of it is the record of what was decided and on what basis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerritorySource {
    /// Resolved from the caller's address against the geo database.
    IpGeo,
    /// Asserted by the operator for a local or private-network caller. An
    /// attestation, not a bypass — and logged as one.
    OperatorDeclared,
    /// Relayed by a peer that saw the end user. The signature proves *who*
    /// asserted it, never that the assertion is true.
    PeerAsserted,
    /// Could not be established.
    Unknown,
}

/// One territorial-eligibility decision, kept as compliance evidence.
///
/// Deliberately minimal. This pairs an address-derived country with a request,
/// which is personal data under the GDPR, so it records what a later audit
/// needs and nothing more — no request body, no output, no full address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerritoryDecision {
    /// The model the decision was about.
    pub model_id: String,
    /// The licence whose grant was applied.
    pub license_id: String,
    /// Resolved ISO 3166-1 alpha-2 country, if one was established.
    pub country: Option<String>,
    /// How that country was established.
    pub source: TerritorySource,
    /// Whether the request was served.
    pub allowed: bool,
    /// Provenance of the territory data, so a decision stays interpretable when
    /// the database is later updated — a bloc's membership or an address's
    /// allocation can both change under it.
    pub database: String,
    /// Unix seconds.
    pub at: u64,
}

/// Operator-set acceptance policy consulted by the model registry when a
/// model is registered. Absent an explicit acknowledgement, `NonCommercial`
/// and unaccepted `CommercialCustom` models are refused at registration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptancePolicy {
    /// When true, `NonCommercial` models may be registered (the operator has
    /// asserted a non-commercial deployment). Maps to `--accept-non-commercial`.
    pub accept_non_commercial: bool,
    /// The set of `CommercialCustom` license IDs the operator has accepted
    /// (e.g. "dinov3", "meta-sam", "gemma"). Maps to repeated
    /// `--accept-license <id>` flags.
    pub accepted_license_ids: Vec<String>,
}

impl AcceptancePolicy {
    /// Returns whether a model with the given tier + license id is admissible.
    pub fn admits(&self, tier: LicenseTier, license_id: Option<&str>) -> bool {
        match tier {
            LicenseTier::Permissive | LicenseTier::Attribution => true,
            LicenseTier::CommercialCustom => match license_id {
                Some(id) => self.accepted_license_ids.iter().any(|a| a == id),
                None => false,
            },
            LicenseTier::NonCommercial => self.accept_non_commercial,
        }
    }
}

/// A serializable peer-fetch hint carried on [`ModelInfo`]. Names a
/// `tenzro://` blob a neighbour can fetch the artifact from, plus the
/// canonical SHA-256 for a transport-independent integrity check.
///
/// Distinct from `tenzro_model::PeerHint`, which is the download-time
/// runtime shape (holds a parsed `TenzroUri`). This record is the wire /
/// storage form persisted on the model catalog entry; the node projects it
/// into the runtime `PeerHint` when building an `ArtifactSpec`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerHintRecord {
    /// `tenzro://blob/<blake3>` or `tenzro://model/<id>@<blake3>` URI.
    pub tenzro_uri: String,
    /// Canonical SHA-256 of the artifact bytes (hex), verified against
    /// the fetched payload regardless of transport.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256_hex: Option<String>,
}

/// Information about an AI model on Tenzro Network
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelInfo {
    /// Unique model identifier
    pub model_id: String,
    /// Model name
    pub name: String,
    /// Model version
    pub version: String,
    /// Model description
    pub description: String,
    /// Model modality
    pub modality: ModelModality,
    /// Model architecture
    pub architecture: String,
    /// Model provider/creator
    pub provider: Address,
    /// Model hash for verification
    pub model_hash: Hash,
    /// Model parameters
    pub parameters: ModelParameters,
    /// Model pricing
    pub pricing: crate::price_card::RateCard,
    /// Model status
    pub status: ModelStatus,
    /// Model metadata
    pub metadata: HashMap<String, String>,
    /// Approximate resident artifact size in bytes (GGUF / ONNX bundle on
    /// disk). `0` means unknown — the router skips memory-fit admission for
    /// models with no declared size.
    #[serde(default)]
    pub size_bytes: u64,
    /// Mixture-of-Experts routing metadata (optional).
    ///
    /// Populated for MoE architectures (Mixtral, DeepSeek-V2/V3, Qwen2-MoE,
    /// OpenMythos RDT-MoE, etc.) to enable routing schedulers to reason
    /// about expert utilization, per-token expert selection cost, and
    /// specialization-aware dispatch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub moe: Option<MoeMetadata>,
    /// Timeseries-specific parameters (forecast horizon, context length, …).
    /// Populated only when `modality == Timeseries`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeseries: Option<TimeseriesParameters>,
    /// Vision encoder parameters (input size, embedding dim, normalization).
    /// Populated for `Image` and image-bearing compound modalities.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vision: Option<VisionParameters>,
    /// Audio model parameters (sample rate, encoder/decoder filenames, langs).
    /// Populated for `Audio` and audio-bearing compound modalities.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audio: Option<AudioParameters>,
    /// Video model parameters (frame size, num frames, fps, embedding dim).
    /// Populated for `Video` modality.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub video: Option<VideoParameters>,
    /// License tier, gating registration against the registry's
    /// `AcceptancePolicy`. Defaults to `Permissive` for models registered
    /// without an explicit tier (e.g. operator-uploaded custom models the
    /// operator is responsible for).
    #[serde(default)]
    pub license_tier: LicenseTier,
    /// Human-readable license name (e.g. "Apache 2.0", "CC-BY-NC-4.0",
    /// "DINOv3 License"). Surfaced for attribution/audit.
    #[serde(default)]
    pub license: String,
    /// Stable license identifier used to match against
    /// `AcceptancePolicy::accepted_license_ids` for `CommercialCustom` tiers
    /// (e.g. "dinov3", "meta-sam", "gemma"). `None` for permissive models.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license_id: Option<String>,
    /// BLAKE3 content address of the artifact bytes, if known. This is the
    /// hash iroh-blobs indexes by, so it is the key a neighbour uses to
    /// fetch the weights over the peer network. `None` for models with no
    /// local downloadable artifact.
    /// The same bytes are also SHA-256'd into `model_hash` (integrity
    /// digest); both are hashes of the same payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blake3_hash: Option<[u8; 32]>,
    /// `tenzro://model/<id>@<blake3>` URI for this artifact, if it has a
    /// content address. Lets clients request the model by content hash
    /// over the peer network instead of by HuggingFace repo path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenzro_uri: Option<String>,
    /// Peers that can serve this artifact over `tenzro://`, freshest last.
    /// Populated opportunistically as neighbours announce providership on
    /// `tenzro/blobs`; the downloader tries these before the HF CDN.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peer_hints: Vec<PeerHintRecord>,
}

impl ModelInfo {
    /// Creates a new model info
    pub fn new(
        model_id: String,
        name: String,
        version: String,
        modality: ModelModality,
        provider: Address,
    ) -> Self {
        Self {
            model_id,
            name,
            version,
            description: String::new(),
            modality,
            architecture: String::new(),
            provider,
            model_hash: Hash::zero(),
            parameters: ModelParameters::default(),
            pricing: crate::price_card::RateCard::default(),
            status: ModelStatus::Pending,
            metadata: HashMap::new(),
            size_bytes: 0,
            moe: None,
            timeseries: None,
            vision: None,
            audio: None,
            video: None,
            license_tier: LicenseTier::Permissive,
            license: String::new(),
            license_id: None,
            blake3_hash: None,
            tenzro_uri: None,
            peer_hints: Vec::new(),
        }
    }

    /// Attach license metadata (tier, human-readable name, and stable id used
    /// for `CommercialCustom` acceptance matching). Set from the catalog entry
    /// when a curated model is registered.
    pub fn with_license(
        mut self,
        tier: LicenseTier,
        license: impl Into<String>,
        license_id: Option<String>,
    ) -> Self {
        self.license_tier = tier;
        self.license = license.into();
        self.license_id = license_id;
        self
    }

    /// Declares the model as a Mixture-of-Experts architecture and
    /// attaches routing metadata.
    pub fn with_moe(mut self, moe: MoeMetadata) -> Self {
        self.moe = Some(moe);
        self
    }

    /// Attach timeseries-specific parameters (forecast horizon, context
    /// length, etc.). Should only be set when `modality == Timeseries`.
    pub fn with_timeseries(mut self, params: TimeseriesParameters) -> Self {
        self.timeseries = Some(params);
        self
    }

    /// Attach vision-encoder parameters (input size, embedding dim,
    /// normalization). Should be set for image and image-bearing compound
    /// modalities.
    pub fn with_vision(mut self, params: VisionParameters) -> Self {
        self.vision = Some(params);
        self
    }

    /// Attach audio-model parameters (sample rate, ONNX bundle filenames,
    /// supported languages). Should be set for `Audio` modality.
    pub fn with_audio(mut self, params: AudioParameters) -> Self {
        self.audio = Some(params);
        self
    }

    /// Attach video-model parameters (frame size, num frames, fps,
    /// embedding dim). Should be set for `Video` modality.
    pub fn with_video(mut self, params: VideoParameters) -> Self {
        self.video = Some(params);
        self
    }

    /// Returns `true` if this model is an MoE architecture with routing
    /// metadata available.
    pub fn is_moe(&self) -> bool {
        self.moe.is_some()
    }

    /// Sets the description
    pub fn with_description(mut self, description: String) -> Self {
        self.description = description;
        self
    }

    /// Sets the architecture
    pub fn with_architecture(mut self, architecture: String) -> Self {
        self.architecture = architecture;
        self
    }

    /// Sets the model hash
    pub fn with_hash(mut self, hash: Hash) -> Self {
        self.model_hash = hash;
        self
    }
}

/// AI model modality
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum ModelModality {
    /// Text-only model
    #[default]
    Text,
    /// Image-only model
    Image,
    /// Audio/speech model
    Audio,
    /// Timeseries forecasting model (numeric inputs/outputs)
    Timeseries,
    /// Video model
    Video,
    /// Text and image (multimodal)
    TextImage,
    /// Text and audio
    TextAudio,
    /// Multiple modalities
    Multimodal,
}

impl ModelModality {
    /// Returns true if this modality supports the requested capability.
    ///
    /// Compound modalities (TextImage, TextAudio, Multimodal) are treated as
    /// supersets of their component modalities. For example, a `TextImage`
    /// model supports both `Text` and `Image` queries, and a `Multimodal`
    /// model supports all modalities.
    ///
    /// This enables inclusive model filtering: searching for `Text` returns
    /// not just `Text` models but also `TextImage`, `TextAudio`, and
    /// `Multimodal` models.
    ///
    /// `Timeseries` is treated as a single-purpose modality — it does not
    /// participate in compound supersets and only matches itself.
    pub fn supports(&self, requested: ModelModality) -> bool {
        if *self == requested {
            return true;
        }
        match *self {
            ModelModality::Multimodal => !matches!(requested, ModelModality::Timeseries),
            ModelModality::TextImage => {
                matches!(requested, ModelModality::Text | ModelModality::Image)
            }
            ModelModality::TextAudio => {
                matches!(requested, ModelModality::Text | ModelModality::Audio)
            }
            _ => false,
        }
    }
}

/// Model parameters and capabilities
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelParameters {
    /// Number of parameters (e.g., 7B, 13B, 70B)
    pub parameter_count: Option<u64>,
    /// Context window size (tokens)
    pub context_window: u32,
    /// Maximum output tokens
    pub max_output_tokens: u32,
    /// Supported input formats
    pub input_formats: Vec<String>,
    /// Supported output formats
    pub output_formats: Vec<String>,
    /// Model capabilities/features
    pub capabilities: Vec<String>,
    /// How this model family converts image geometry into billable tokens.
    pub image_tokenization: ImageTokenization,
}

impl Default for ModelParameters {
    fn default() -> Self {
        Self {
            parameter_count: None,
            context_window: 4096,
            max_output_tokens: 2048,
            input_formats: vec!["text".to_string()],
            output_formats: vec!["text".to_string()],
            capabilities: Vec::new(),
            image_tokenization: ImageTokenization::default(),
        }
    }
}

/// Mixture-of-Experts routing metadata for MoE architectures.
///
/// Captures the parameters an inference router needs to reason about
/// per-token cost, expert utilization, and specialization-aware dispatch.
/// Designed to cover Mixtral 8x7B / 8x22B, DeepSeek-V2 / V3 (shared +
/// routed experts), Qwen2-MoE, and recurrent-depth MoE stacks such as
/// OpenMythos.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoeMetadata {
    /// Total number of routed experts in the model (e.g., 8 for Mixtral 8x7B,
    /// 64 for Qwen2-MoE).
    pub num_experts: u32,
    /// Number of experts activated per token (top-k routing). Typical
    /// values: 2 for Mixtral, 6 for DeepSeek-V2, 8 for Qwen2-MoE.
    pub experts_per_token: u8,
    /// Shared ("always-on") experts that process every token alongside
    /// the routed experts. Used by DeepSeekMoE-style architectures;
    /// zero for Mixtral-style models.
    #[serde(default)]
    pub shared_experts: u32,
    /// Parameters per expert (in billions, scaled x10 for fixed-point —
    /// e.g., 70 = 7.0B). `None` when unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params_per_expert_x10: Option<u32>,
    /// Routing strategy used by the gating network.
    pub routing_strategy: MoeRoutingStrategy,
    /// Auxiliary load-balancing loss coefficient (x10000 fixed point).
    /// Helps schedulers estimate how evenly load spreads across experts.
    /// `None` when unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_balance_coef_x10000: Option<u32>,
    /// Attention mechanism variant (e.g., "mla" for Multi-head Latent
    /// Attention, "mha", "mqa", "gqa").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attention_type: Option<String>,
    /// Optional per-expert specialization labels (ordered by expert
    /// index). E.g., `["math", "code", "reasoning", ...]`. Routers can
    /// use these to bias toward specialized experts for known task
    /// categories.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expert_specialization: Option<Vec<String>>,
    /// Expert capacity factor (x100 fixed point — e.g., 125 = 1.25).
    /// Drives per-expert token budget: `capacity = ceil(tokens * top_k *
    /// capacity_factor / num_experts)`. `None` defaults to 1.0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capacity_factor_x100: Option<u32>,
}

impl MoeMetadata {
    /// Construct a minimal MoE metadata block from the required fields.
    pub fn new(
        num_experts: u32,
        experts_per_token: u8,
        routing_strategy: MoeRoutingStrategy,
    ) -> Self {
        Self {
            num_experts,
            experts_per_token,
            shared_experts: 0,
            params_per_expert_x10: None,
            routing_strategy,
            load_balance_coef_x10000: None,
            attention_type: None,
            expert_specialization: None,
            capacity_factor_x100: None,
        }
    }

    /// Declare shared ("always-on") experts.
    pub fn with_shared_experts(mut self, shared: u32) -> Self {
        self.shared_experts = shared;
        self
    }

    /// Declare parameters-per-expert in billions (scaled x10).
    pub fn with_params_per_expert_x10(mut self, params_x10: u32) -> Self {
        self.params_per_expert_x10 = Some(params_x10);
        self
    }

    /// Declare the attention variant (e.g., "mla", "gqa").
    pub fn with_attention_type(mut self, attn: impl Into<String>) -> Self {
        self.attention_type = Some(attn.into());
        self
    }

    /// Attach a per-expert specialization label list.
    pub fn with_expert_specialization(mut self, labels: Vec<String>) -> Self {
        self.expert_specialization = Some(labels);
        self
    }

    /// Declare the expert capacity factor as a x100 fixed-point value.
    pub fn with_capacity_factor_x100(mut self, cf_x100: u32) -> Self {
        self.capacity_factor_x100 = Some(cf_x100);
        self
    }

    /// Total activated experts per token (routed top-k + shared).
    pub fn active_experts_per_token(&self) -> u32 {
        self.experts_per_token as u32 + self.shared_experts
    }

    /// Total parameters across all routed experts, in billions scaled x10.
    /// Returns `None` if `params_per_expert_x10` is unset.
    pub fn total_routed_params_x10(&self) -> Option<u64> {
        self.params_per_expert_x10
            .map(|p| p as u64 * self.num_experts as u64)
    }

    /// Active parameters per token, in billions scaled x10. Useful for
    /// cost/latency estimation since MoE inference only pays for
    /// activated experts, not the total parameter count.
    pub fn active_params_per_token_x10(&self) -> Option<u64> {
        self.params_per_expert_x10
            .map(|p| p as u64 * self.active_experts_per_token() as u64)
    }
}

/// Gating-network routing strategy for an MoE model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MoeRoutingStrategy {
    /// Classic top-k expert selection (Mixtral, Qwen2-MoE).
    TopK,
    /// Top-p (nucleus) expert selection — dynamic experts-per-token
    /// based on cumulative gate probability.
    TopP,
    /// Expert-Choice routing — each expert picks its top-k tokens
    /// (Zhou et al., 2022).
    ExpertChoice,
    /// Switch Transformer single-expert routing (top-1).
    Switch,
    /// Soft routing (all experts weighted, no hard top-k).
    Soft,
    /// Sinkhorn / BASE-layer balanced assignment.
    Sinkhorn,
    /// Hash-based fixed routing (no learned gate).
    Hash,
    /// Custom / proprietary routing.
    Custom,
}

/// Timeseries forecasting model parameters.
///
/// Captures the shape contract of an ONNX timeseries model: how many
/// historical points it consumes (`context_length`), how many points it
/// emits (`max_horizon`), how many quantiles per step (`n_quantiles`,
/// `1` for point forecasts), and how many parallel input series it
/// accepts (`num_features`, `1` for univariate). Used by
/// `TimeseriesRuntime` and the catalog-driven loader to validate
/// inputs before invoking ORT.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeseriesParameters {
    /// Number of historical points the model conditions on.
    pub context_length: u32,
    /// Maximum number of forecast steps the model can emit in one pass.
    pub max_horizon: u32,
    /// Number of quantiles emitted per step (1 = point forecast,
    /// >1 = quantile forecast).
    pub n_quantiles: u32,
    /// Number of input feature channels (1 = univariate;
    /// >1 = multivariate / covariate-aware).
    pub num_features: u32,
}

impl TimeseriesParameters {
    /// Construct univariate point-forecast parameters.
    pub fn univariate(context_length: u32, max_horizon: u32) -> Self {
        Self {
            context_length,
            max_horizon,
            n_quantiles: 1,
            num_features: 1,
        }
    }

    /// Construct quantile-forecast parameters.
    pub fn with_quantiles(mut self, n_quantiles: u32) -> Self {
        self.n_quantiles = n_quantiles;
        self
    }

    /// Construct multivariate parameters.
    pub fn with_features(mut self, num_features: u32) -> Self {
        self.num_features = num_features;
        self
    }
}

/// Vision encoder parameters.
///
/// Captures everything needed to feed an image into an ONNX vision
/// encoder: spatial input size, output embedding dimensionality, the
/// normalization recipe (e.g., "clip", "imagenet", "siglip"), and the
/// list of accepted image container formats. Used by `VisionRuntime`
/// and the catalog-driven loader.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VisionParameters {
    /// Square input edge in pixels (e.g., 224, 256, 336, 384).
    pub input_size: u32,
    /// Output embedding dimensionality (e.g., 512 for CLIP B/32,
    /// 1024 for DINOv2 large).
    pub embedding_dim: u32,
    /// Normalization recipe key — `"clip" | "imagenet" | "siglip"`.
    pub normalization: String,
    /// Accepted image container formats (e.g., `["png", "jpeg", "webp"]`).
    pub image_formats: Vec<String>,
}

/// Audio model parameters.
///
/// Audio ONNX models are typically multi-file bundles
/// (encoder + decoder + optional joiner for RNN-T style models). The
/// filenames map to entries inside the HuggingFace repo. Sample rate
/// is the canonical input rate the model expects; preprocessing
/// resamples to it. `languages` carries ISO-639 codes for ASR models
/// that advertise specific language coverage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AudioParameters {
    /// Required input sample rate in Hz (typically 16000).
    pub sample_rate: u32,
    /// Encoder ONNX filename inside the HF repo bundle.
    pub encoder_filename: String,
    /// Decoder ONNX filename (Whisper-style, RNN-T joiner-decoder split).
    /// `None` for single-encoder models like Moonshine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decoder_filename: Option<String>,
    /// Joiner ONNX filename (RNN-T architectures, e.g., Parakeet TDT).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub joiner_filename: Option<String>,
    /// Maximum audio duration the model can process in one pass.
    pub max_audio_seconds: u32,
    /// Supported languages as ISO-639 codes (e.g., `["en", "de", "fr"]`).
    /// Empty for monolingual models or where docs don't specify.
    #[serde(default)]
    pub languages: Vec<String>,
}

/// Video model parameters.
///
/// Captures the spatio-temporal input contract for a video encoder:
/// per-frame spatial size, the number of frames consumed per inference,
/// the target frames-per-second the model was trained on (used for
/// stride during preprocessing), and the output embedding dimensionality.
/// The type exists but the catalog is empty until a permissive,
/// ONNX-exportable encoder is available.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VideoParameters {
    /// Square frame edge in pixels.
    pub frame_size: u32,
    /// Number of frames consumed per inference (e.g., 16 for VideoMAE).
    pub num_frames: u32,
    /// Target FPS the model was trained on. Drives temporal stride
    /// during frame extraction.
    pub fps: u32,
    /// Output embedding dimensionality.
    pub embedding_dim: u32,
}

/// Model operational status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModelStatus {
    /// Registration pending verification
    Pending,
    /// Active and available for inference
    Active,
    /// Temporarily inactive
    Inactive,
}

/// An inference request to an AI model
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceRequest {
    /// Request ID
    pub request_id: String,
    /// Model to use
    pub model_id: String,
    /// Requester address
    pub requester: Address,
    /// Input data
    pub input: Vec<u8>,
    /// Inference parameters
    pub parameters: InferenceParameters,
    /// Maximum price willing to pay (in smallest TNZO unit)
    pub max_price: u64,
    /// Request timestamp
    pub timestamp: Timestamp,
    /// Optional callback address
    pub callback: Option<Address>,
}

impl InferenceRequest {
    /// Creates a new inference request
    pub fn new(model_id: String, requester: Address, input: Vec<u8>, max_price: u64) -> Self {
        Self {
            request_id: uuid::Uuid::new_v4().to_string(),
            model_id,
            requester,
            input,
            parameters: InferenceParameters::default(),
            max_price,
            timestamp: Timestamp::now(),
            callback: None,
        }
    }

    /// Sets inference parameters
    pub fn with_parameters(mut self, parameters: InferenceParameters) -> Self {
        self.parameters = parameters;
        self
    }

    /// Sets callback address
    pub fn with_callback(mut self, callback: Address) -> Self {
        self.callback = Some(callback);
        self
    }
}

/// Parameters for model inference
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceParameters {
    /// Temperature for sampling
    pub temperature: Option<u32>, // Stored as fixed-point (e.g., 100 = 1.0)
    /// Top-p sampling
    pub top_p: Option<u32>, // Stored as fixed-point
    /// Top-k sampling
    pub top_k: Option<u32>,
    /// Maximum tokens to generate
    pub max_tokens: Option<u32>,
    /// Stop sequences
    pub stop_sequences: Vec<String>,
    /// Additional custom parameters
    pub custom: HashMap<String, String>,
}

impl Default for InferenceParameters {
    fn default() -> Self {
        Self {
            temperature: Some(100), // 1.0
            top_p: None,
            top_k: None,
            max_tokens: None,
            stop_sequences: Vec::new(),
            custom: HashMap::new(),
        }
    }
}

/// Response from model inference
///
/// EU AI Act Article 50 (effective 2026-08-02) requires generative-AI outputs
/// to carry both (a) a machine-readable disclosure that the content is
/// AI-generated and (b) a verifiable provenance manifest. Both fields here
/// are always populated by `tenzro-model::routing` for served inferences:
/// `synthetic_content` is unconditionally `true` (every inference response is
/// AI-generated by definition) and `provenance` carries a signed
/// [`ContentProvenanceManifest`] when a `ProvenanceSigner` is wired into the router.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceResponse {
    /// Request ID this response is for
    pub request_id: String,
    /// Response ID
    pub response_id: String,
    /// Model that generated the response
    pub model_id: String,
    /// Provider that served the request
    pub provider: Address,
    /// Output data
    pub output: Vec<u8>,
    /// Response metadata
    pub metadata: InferenceMetadata,
    /// Actual price charged (in smallest TNZO unit)
    #[serde(with = "crate::primitives::u128_serde")]
    pub price: u128,
    /// Response timestamp
    pub timestamp: Timestamp,
    /// EU AI Act Article 50(2) — content is machine-generated. Always `true`
    /// for genuine inference responses; deserialized as `true` by default so
    /// integrations that build responses by hand cannot accidentally drop the
    /// disclosure.
    #[serde(default = "default_synthetic_content")]
    pub synthetic_content: bool,
    /// EU AI Act Article 50(2) — content provenance. `None` only for in-memory
    /// transient responses that haven't been signed yet (e.g. mid-router). All
    /// responses returned to RPC/MCP/A2A clients have this populated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<ContentProvenanceManifest>,
    /// Signed jurisdiction receipt attesting where this inference ran.
    /// Present when the request pinned a jurisdiction
    /// (`parameters.custom["jurisdiction"]`) and the serving node holds a
    /// declared [`JurisdictionClaim`] plus a receipt signer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jurisdiction_receipt: Option<JurisdictionReceipt>,
}

fn default_synthetic_content() -> bool {
    true
}

impl InferenceResponse {
    /// Creates a new inference response. The result is marked as
    /// `synthetic_content = true` automatically per EU AI Act Article 50.
    /// Callers should attach a [`ContentProvenanceManifest`] via [`with_provenance`]
    /// before publishing the response off the node.
    ///
    /// [`with_provenance`]: InferenceResponse::with_provenance
    pub fn new(
        request_id: String,
        model_id: String,
        provider: Address,
        output: Vec<u8>,
        price: u128,
    ) -> Self {
        Self {
            request_id,
            response_id: uuid::Uuid::new_v4().to_string(),
            model_id,
            provider,
            output,
            metadata: InferenceMetadata::default(),
            price,
            timestamp: Timestamp::now(),
            synthetic_content: true,
            provenance: None,
            jurisdiction_receipt: None,
        }
    }

    /// Builder helper to attach a signed provenance manifest before the
    /// response leaves the inference router.
    pub fn with_provenance(mut self, manifest: ContentProvenanceManifest) -> Self {
        self.provenance = Some(manifest);
        self
    }

    /// Builder helper to attach a signed jurisdiction receipt before the
    /// response leaves the inference router.
    pub fn with_jurisdiction_receipt(mut self, receipt: JurisdictionReceipt) -> Self {
        self.jurisdiction_receipt = Some(receipt);
        self
    }
}

/// Content provenance manifest — a C2PA-style attestation that an AI output
/// was produced on Tenzro Network by a specific model + provider, signed by
/// the provider's key. The manifest is small enough to embed in a JSON-RPC
/// response and self-contained enough to verify offline given the signer's
/// public key.
///
/// This is intentionally protocol-agnostic: when the C2PA Content Credentials
/// final spec under the EU AI Office Code of Practice (June 2026) is
/// finalized, the on-the-wire encoding can be swapped for a `c2pa-rs`
/// manifest store while keeping this type as the in-memory representation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentProvenanceManifest {
    /// SHA-256 of the inference output bytes (`InferenceResponse.output`).
    /// Acts as the lookup key for `tenzro_getContentProvenance(content_hash)`.
    pub content_hash: Hash,
    /// Model that produced the content (mirror of `InferenceResponse.model_id`).
    pub model_id: String,
    /// Provider that ran the inference (mirror of `InferenceResponse.provider`).
    pub provider: Address,
    /// Wall-clock timestamp at which the manifest was signed.
    pub signed_at: Timestamp,
    /// Content classification — `"ai-generated"` for ordinary inference
    /// outputs, `"deepfake"` for outputs that imitate a real person, place,
    /// or event (EU AI Act Art. 50(4) labeling).
    pub assertion: String,
    /// Signer's public key (raw bytes — Ed25519 = 32B, secp256k1 = 33B).
    pub signer_public_key: Vec<u8>,
    /// Detached signature over the canonical preimage:
    /// `content_hash || model_id (utf8) || provider (32B) || signed_at_ms (le_u64) || assertion (utf8)`.
    pub signature: Vec<u8>,
    /// Algorithm tag matching `signature` — `"ed25519"` or `"secp256k1"`.
    pub algorithm: String,
}

impl ContentProvenanceManifest {
    /// Canonical preimage used to verify [`signature`]. Recomputed by both
    /// the signer (in `tenzro-model::provenance`) and any third-party
    /// verifier — encoding here is the single source of truth.
    ///
    /// [`signature`]: ContentProvenanceManifest::signature
    pub fn canonical_preimage(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            self.content_hash.0.len()
                + self.model_id.len()
                + self.provider.0.len()
                + 8
                + self.assertion.len(),
        );
        buf.extend_from_slice(&self.content_hash.0);
        buf.extend_from_slice(self.model_id.as_bytes());
        buf.extend_from_slice(&self.provider.0);
        buf.extend_from_slice(&self.signed_at.as_millis().to_le_bytes());
        buf.extend_from_slice(self.assertion.as_bytes());
        buf
    }
}

/// A provider's declared serving jurisdiction — an attestation-bound
/// locality claim, not a cryptographic proof of geographic location.
///
/// The claim states the legal jurisdiction the operator asserts the node
/// runs under (ISO 3166-1 alpha-2 country code, plus optional regulatory
/// bloc memberships such as `EU` or `EEA`). When the node runs inside a
/// TEE, `attestation_hash` binds the claim to a specific enclave's
/// attestation report, so the claim cannot be replayed onto different
/// hardware. Relying parties should treat the claim as
/// operator-asserted-and-attestation-pinned: the attestation proves *which
/// enclave* made the claim, and slashing/reputation punishes false
/// declarations — it does not geolocate the machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JurisdictionClaim {
    /// ISO 3166-1 alpha-2 country code, uppercase (e.g. `"DE"`, `"SG"`).
    pub country: String,
    /// Regulatory bloc memberships the country claim implies, uppercase
    /// free-form tokens (e.g. `["EU", "EEA"]`). Matched verbatim against
    /// request pins — the protocol hard-codes no bloc vocabulary.
    #[serde(default)]
    pub blocs: Vec<String>,
    /// SHA-256 of the TEE attestation report the claim is bound to.
    /// `None` for non-TEE nodes: the claim is then operator-asserted only.
    // NOT `skip_serializing_if` — this rides the bincode gossip announcement
    // inside `AdvertisedCapacity.jurisdiction`. Dormant only because that
    // field is `None` today; the first operator to declare a jurisdiction
    // would have desynchronised every announcement they sent.
    #[serde(default)]
    pub attestation_hash: Option<Hash>,
    /// When the operator declared (or last re-attested) this claim.
    pub declared_at: Timestamp,
}

impl JurisdictionClaim {
    /// Whether this claim satisfies one request pin token. Tokens are
    /// compared case-insensitively against the country code and every
    /// declared bloc.
    pub fn matches(&self, token: &str) -> bool {
        let token = token.trim();
        if token.is_empty() {
            return false;
        }
        self.country.eq_ignore_ascii_case(token)
            || self.blocs.iter().any(|b| b.eq_ignore_ascii_case(token))
    }

    /// Whether this claim satisfies any of the request's pin tokens.
    pub fn matches_any<'a, I: IntoIterator<Item = &'a str>>(&self, tokens: I) -> bool {
        tokens.into_iter().any(|t| self.matches(t))
    }
}

/// Signed jurisdiction receipt for one inference — the provider's
/// attestation-bound statement of *where* a specific request was served.
/// Embeds in the [`InferenceResponse`] and verifies offline given the
/// signer's public key, mirroring [`ContentProvenanceManifest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JurisdictionReceipt {
    /// SHA-256 of the request input bytes (`InferenceRequest.input`).
    pub request_hash: Hash,
    /// SHA-256 of the inference output bytes (`InferenceResponse.output`).
    pub response_hash: Hash,
    /// Model that served the request.
    pub model_id: String,
    /// Provider that served the request.
    pub provider: Address,
    /// The jurisdiction claim in force when the request was served.
    pub jurisdiction: JurisdictionClaim,
    /// Wall-clock timestamp at which the receipt was signed.
    pub signed_at: Timestamp,
    /// The P-256 leg (`x || y`, 64 bytes) of the serving node's hardware
    /// identity key, which signed the batch holding the receipt.
    pub signer_public_key: Vec<u8>,
    /// The ML-DSA-65 leg of the serving node's hardware identity key, when
    /// its hardware holds one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_pq_key: Option<Vec<u8>>,
    /// The JSON of the batched signature (`tenzro_crypto::batch`) over
    /// [`canonical_preimage`]; `None` only before the receipt is signed.
    ///
    /// [`canonical_preimage`]: JurisdictionReceipt::canonical_preimage
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batched: Option<Vec<u8>>,
}

impl JurisdictionReceipt {
    /// Canonical preimage used to verify [`batched`]. Variable-length
    /// fields are length-prefixed (le_u32) so the encoding is unambiguous.
    ///
    /// Layout: `request_hash(32) || response_hash(32) || len(model_id) ||
    /// model_id || provider || len(country) || country || bloc_count ||
    /// (len(bloc) || bloc)* || attestation_flag(1) || [attestation_hash(32)]
    /// || declared_at_ms(le_u64) || signed_at_ms(le_u64)`.
    ///
    /// [`batched`]: JurisdictionReceipt::batched
    pub fn canonical_preimage(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(160 + self.model_id.len());
        buf.extend_from_slice(&self.request_hash.0);
        buf.extend_from_slice(&self.response_hash.0);
        buf.extend_from_slice(&(self.model_id.len() as u32).to_le_bytes());
        buf.extend_from_slice(self.model_id.as_bytes());
        buf.extend_from_slice(&self.provider.0);
        let j = &self.jurisdiction;
        buf.extend_from_slice(&(j.country.len() as u32).to_le_bytes());
        buf.extend_from_slice(j.country.as_bytes());
        buf.extend_from_slice(&(j.blocs.len() as u32).to_le_bytes());
        for bloc in &j.blocs {
            buf.extend_from_slice(&(bloc.len() as u32).to_le_bytes());
            buf.extend_from_slice(bloc.as_bytes());
        }
        match &j.attestation_hash {
            Some(h) => {
                buf.push(1);
                buf.extend_from_slice(&h.0);
            }
            None => buf.push(0),
        }
        buf.extend_from_slice(&j.declared_at.as_millis().to_le_bytes());
        buf.extend_from_slice(&self.signed_at.as_millis().to_le_bytes());
        buf
    }
}

/// Work one call did, as quantities under meter keys
/// ([`crate::meter::parse_key`]): `input_tokens`, `output_tokens@priority`,
/// `audio_out_ms`, `action_chunks`, ...
///
/// The keys are data. A unit is a record in the on-chain unit registry, so a
/// model type that bills on something new carries it here without a change to
/// this type, to the receipts that sign it or to the settlement that prices
/// it. A key with a zero quantity is never stored: an absent key and a zero
/// one are the same meter, so two meters for the same work compare and hash
/// equal.
///
/// The typed accessors below read the units the network starts with; they are
/// conveniences over the same map, not a second representation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BillableUnits {
    quantities: std::collections::BTreeMap<String, u128>,
}

/// Domain tag of [`BillableUnits::canonical_bytes`].
pub const METER_DOMAIN: &[u8] = b"tenzro/meter/v1";

impl BillableUnits {
    /// An empty meter.
    pub fn new() -> Self {
        Self::default()
    }

    /// The quantity under `key`, zero when absent.
    pub fn get(&self, key: &str) -> u128 {
        self.quantities.get(key).copied().unwrap_or(0)
    }

    /// Record `quantity` under `key`, replacing what was there. Zero removes
    /// the key. Refuses a key that is not a meter key.
    pub fn set(&mut self, key: &str, quantity: u128) -> Result<(), crate::meter::MeterError> {
        crate::meter::parse_key(key)?;
        if quantity == 0 {
            self.quantities.remove(key);
        } else {
            self.quantities.insert(key.to_string(), quantity);
        }
        Ok(())
    }

    /// Add `quantity` under `key`, refusing an overflow.
    pub fn add(&mut self, key: &str, quantity: u128) -> Result<(), crate::meter::MeterError> {
        let total = self
            .get(key)
            .checked_add(quantity)
            .ok_or_else(|| crate::meter::MeterError::Overflow(key.to_string()))?;
        self.set(key, total)
    }

    /// Builder form of [`Self::set`] for the well-known keys this crate
    /// names; a bad key is a programming error there.
    fn with(mut self, key: &str, quantity: u128) -> Self {
        self.set(key, quantity).expect("well-known meter key");
        self
    }

    /// Every key with its quantity, in key order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, u128)> {
        self.quantities.iter().map(|(k, v)| (k.as_str(), *v))
    }

    /// Number of keys recorded.
    pub fn len(&self) -> usize {
        self.quantities.len()
    }

    /// Whether no work was recorded.
    pub fn is_empty(&self) -> bool {
        self.quantities.is_empty()
    }

    /// Sum of the quantities of `unit` across every tier.
    pub fn unit_total(&self, unit: &str) -> u128 {
        self.iter()
            .filter(|(k, _)| {
                crate::meter::parse_key(k)
                    .map(|(u, _)| u == unit)
                    .unwrap_or(false)
            })
            .fold(0u128, |acc, (_, v)| acc.saturating_add(v))
    }

    /// Accumulate another meter into this one, saturating. For running
    /// totals; a charge is computed from one call's meter, never from a
    /// saturated total.
    pub fn accumulate(&mut self, other: &Self) {
        for (k, v) in other.iter() {
            let total = self.get(k).saturating_add(v);
            self.quantities.insert(k.to_string(), total);
        }
    }

    /// The bytes a signature over this meter covers: the domain, the number
    /// of keys, then each key (length-prefixed) and its quantity, in key
    /// order.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = METER_DOMAIN.to_vec();
        out.extend_from_slice(&(self.quantities.len() as u32).to_le_bytes());
        for (k, v) in &self.quantities {
            out.extend_from_slice(&(k.len() as u32).to_le_bytes());
            out.extend_from_slice(k.as_bytes());
            out.extend_from_slice(&v.to_le_bytes());
        }
        out
    }

    fn get_u32(&self, key: &str) -> u32 {
        u32::try_from(self.unit_total(key)).unwrap_or(u32::MAX)
    }

    fn get_u64(&self, key: &str) -> u64 {
        u64::try_from(self.unit_total(key)).unwrap_or(u64::MAX)
    }

    /// Units for a text call: prompt and completion tokens only.
    pub fn tokens(input_tokens: u32, output_tokens: u32) -> Self {
        Self::new()
            .with(unit::INPUT_TOKENS, input_tokens as u128)
            .with(unit::OUTPUT_TOKENS, output_tokens as u128)
    }

    /// [`Self::tokens`], but every key carries `tier` (see
    /// [`crate::meter::key`]) so a provider's rate card can price it on its
    /// own line, separately from the plain key — [`Self::unit_total`] still
    /// sums a unit across every tier for anything that does not care which.
    /// Used for the spot (pre-emptible, demand-paid idle capacity) tier;
    /// `None` is the ordinary, untiered price.
    pub fn tokens_in_tier(input_tokens: u32, output_tokens: u32, tier: Option<&str>) -> Self {
        Self::new()
            .with(
                &crate::meter::key(unit::INPUT_TOKENS, tier),
                input_tokens as u128,
            )
            .with(
                &crate::meter::key(unit::OUTPUT_TOKENS, tier),
                output_tokens as u128,
            )
    }

    /// Records prompt tokens served from, and written into, the prefix cache.
    pub fn with_cache(self, read_tokens: u32, write_tokens: u32) -> Self {
        self.with(unit::CACHED_READ_TOKENS, read_tokens as u128)
            .with(unit::CACHED_WRITE_TOKENS, write_tokens as u128)
    }

    /// Records tokens generated but not emitted.
    pub fn with_reasoning_tokens(self, tokens: u32) -> Self {
        self.with(unit::REASONING_TOKENS, tokens as u128)
    }

    /// Records recurrent reasoning loops executed.
    pub fn with_reasoning_loops(self, loops: u32) -> Self {
        self.with(unit::REASONING_LOOPS, loops as u128)
    }

    /// Records tokens derived from image geometry.
    pub fn with_image_tokens(self, image_tokens: u32) -> Self {
        self.with(unit::IMAGE_TOKENS, image_tokens as u128)
    }

    /// Records audio duration consumed, in milliseconds.
    pub fn with_audio_ms(self, audio_ms: u64) -> Self {
        self.with(unit::AUDIO_MS, audio_ms as u128)
    }

    /// Records video duration consumed, in milliseconds.
    pub fn with_video_ms(self, video_ms: u64) -> Self {
        self.with(unit::VIDEO_MS, video_ms as u128)
    }

    /// Records denoising work: width × height × steps × frames. The frames
    /// are a factor of it, not a second charge, so they are not recorded
    /// separately.
    pub fn with_pixel_steps(self, pixel_steps: u128) -> Self {
        self.with(unit::PIXEL_STEPS, pixel_steps)
    }

    /// Records frames processed or produced.
    pub fn with_frames(self, frames: u32) -> Self {
        self.with(unit::FRAMES, frames as u128)
    }

    /// Records characters of text spoken.
    pub fn with_characters(self, characters: u32) -> Self {
        self.with(unit::CHARACTERS, characters as u128)
    }

    /// Records (query, document) pairs scored.
    pub fn with_rerank_pairs(self, pairs: u32) -> Self {
        self.with(unit::RERANK_PAIRS, pairs as u128)
    }

    /// Records questions a decision model answered.
    pub fn with_decision_questions(self, questions: u32) -> Self {
        self.with(unit::DECISION_QUESTIONS, questions as u128)
    }

    /// Records tokens trained.
    pub fn with_trained_tokens(self, tokens: u64) -> Self {
        self.with(unit::TRAINED_TOKENS, tokens as u128)
    }

    /// Records audio produced, in milliseconds.
    pub fn with_audio_out_ms(self, audio_out_ms: u64) -> Self {
        self.with(unit::AUDIO_OUT_MS, audio_out_ms as u128)
    }

    /// Records forecast points emitted: series × horizon steps, all quantile
    /// levels at a step counted as one point.
    pub fn with_forecast_points(self, points: u32) -> Self {
        self.with(unit::FORECAST_POINTS, points as u128)
    }

    /// Records a world-model job's simulated length and booked session hold,
    /// both in milliseconds.
    pub fn with_world(self, simulated_ms: u64, session_hold_ms: u64) -> Self {
        self.with(unit::SIMULATED_MS, simulated_ms as u128)
            .with(unit::SESSION_HOLD_MS, session_hold_ms as u128)
    }

    pub fn input_tokens(&self) -> u32 {
        self.get_u32(unit::INPUT_TOKENS)
    }
    pub fn output_tokens(&self) -> u32 {
        self.get_u32(unit::OUTPUT_TOKENS)
    }
    pub fn reasoning_tokens(&self) -> u32 {
        self.get_u32(unit::REASONING_TOKENS)
    }
    pub fn cached_read_tokens(&self) -> u32 {
        self.get_u32(unit::CACHED_READ_TOKENS)
    }
    pub fn cached_write_tokens(&self) -> u32 {
        self.get_u32(unit::CACHED_WRITE_TOKENS)
    }
    pub fn reasoning_loops(&self) -> u32 {
        self.get_u32(unit::REASONING_LOOPS)
    }
    pub fn image_tokens(&self) -> u32 {
        self.get_u32(unit::IMAGE_TOKENS)
    }
    pub fn audio_ms(&self) -> u64 {
        self.get_u64(unit::AUDIO_MS)
    }
    pub fn video_ms(&self) -> u64 {
        self.get_u64(unit::VIDEO_MS)
    }
    pub fn pixel_steps(&self) -> u128 {
        self.unit_total(unit::PIXEL_STEPS)
    }
    pub fn frames(&self) -> u32 {
        self.get_u32(unit::FRAMES)
    }
    pub fn characters(&self) -> u32 {
        self.get_u32(unit::CHARACTERS)
    }
    pub fn rerank_pairs(&self) -> u32 {
        self.get_u32(unit::RERANK_PAIRS)
    }
    pub fn decision_questions(&self) -> u32 {
        self.get_u32(unit::DECISION_QUESTIONS)
    }
    pub fn trained_tokens(&self) -> u64 {
        self.get_u64(unit::TRAINED_TOKENS)
    }
    pub fn audio_out_ms(&self) -> u64 {
        self.get_u64(unit::AUDIO_OUT_MS)
    }
    pub fn forecast_points(&self) -> u32 {
        self.get_u32(unit::FORECAST_POINTS)
    }
    pub fn simulated_ms(&self) -> u64 {
        self.get_u64(unit::SIMULATED_MS)
    }
    pub fn session_hold_ms(&self) -> u64 {
        self.get_u64(unit::SESSION_HOLD_MS)
    }

    /// The whole prompt as an OpenAI-compatible caller counts it: the fresh
    /// prefill plus the share served from cache. Cache writes are excluded:
    /// a token written into cache was prefilled fresh and is already in
    /// `input_tokens`.
    pub fn prompt_tokens(&self) -> u32 {
        self.input_tokens()
            .saturating_add(self.cached_read_tokens())
    }

    /// Tokens of every kind: prompt, completion, hidden, cache, and
    /// image-derived.
    pub fn total_tokens(&self) -> u32 {
        self.input_tokens()
            .saturating_add(self.output_tokens())
            .saturating_add(self.reasoning_tokens())
            .saturating_add(self.cached_read_tokens())
            .saturating_add(self.cached_write_tokens())
            .saturating_add(self.image_tokens())
    }
}

/// A human-readable format carries the meter as a JSON object of key to
/// quantity, a quantity above `u64::MAX` as a decimal string; a fixed-layout
/// format carries the map natively. Either way a decoded meter is checked:
/// every key must be a meter key and no quantity may be zero.
mod billable_units_serde {
    use super::BillableUnits;
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::BTreeMap;

    #[derive(Serialize, Deserialize)]
    struct Q(#[serde(with = "crate::primitives::u128_serde")] u128);

    impl Serialize for BillableUnits {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            if s.is_human_readable() {
                let m: BTreeMap<&str, Q> = self.iter().map(|(k, v)| (k, Q(v))).collect();
                m.serialize(s)
            } else {
                self.quantities.serialize(s)
            }
        }
    }

    impl<'de> Deserialize<'de> for BillableUnits {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            let raw: BTreeMap<String, u128> = if d.is_human_readable() {
                BTreeMap::<String, Q>::deserialize(d)?
                    .into_iter()
                    .map(|(k, q)| (k, q.0))
                    .collect()
            } else {
                BTreeMap::<String, u128>::deserialize(d)?
            };
            let mut out = BillableUnits::default();
            for (k, v) in raw {
                if v == 0 {
                    return Err(D::Error::custom(format!("meter key '{k}' has quantity 0")));
                }
                out.set(&k, v).map_err(D::Error::custom)?;
            }
            Ok(out)
        }
    }
}

/// How a model family converts image geometry into billable tokens.
///
/// Image inputs carry no tokenizer output to count, so the token charge has to
/// be derived from width and height. Families disagree on how: a fixed-grid ViT
/// encoder produces one token per patch, a tiling vision-language model charges
/// per tile plus a thumbnail pass, and a pooled embedding encoder charges the
/// same regardless of input size. The descriptor lives on
/// [`ModelParameters`] so each catalog entry declares its own rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImageTokenization {
    /// One flat charge per image regardless of geometry. Pooled encoders
    /// (CLIP, SigLIP, DINOv3) resize every input to a fixed resolution, so the
    /// work does not vary with what the caller submitted.
    Flat {
        /// Tokens charged per image.
        tokens_per_image: u32,
    },
    /// One token per `patch_size × patch_size` patch of the input, capped at
    /// `max_tokens`. Matches the native-resolution ViT encoders used by
    /// vision-language models that do not tile.
    PatchGrid {
        /// Patch edge length in pixels.
        patch_size: u32,
        /// Ceiling on derived tokens, mirroring the encoder's own cap.
        max_tokens: u32,
    },
    /// A `base_tokens` low-resolution pass plus `tokens_per_tile` for each
    /// `tile_size × tile_size` tile of the input, up to `max_tiles`. Matches
    /// the tiling scheme used by high-resolution vision-language models.
    Tiled {
        /// Tile edge length in pixels.
        tile_size: u32,
        /// Tokens charged per tile.
        tokens_per_tile: u32,
        /// Tokens charged for the low-resolution pass over the whole image.
        base_tokens: u32,
        /// Ceiling on the number of tiles charged.
        max_tiles: u32,
    },
}

impl Default for ImageTokenization {
    /// A 14-pixel patch grid capped at 4096 tokens — the most common vision
    /// encoder geometry, and the safe assumption for a catalog entry that has
    /// not declared its own rule.
    fn default() -> Self {
        Self::PatchGrid {
            patch_size: 14,
            max_tokens: 4096,
        }
    }
}

impl ImageTokenization {
    /// Derives the billable token count for an image of the given geometry.
    ///
    /// A zero-area image yields zero tokens. Patch and tile counts round up so
    /// a partial patch is charged rather than discarded.
    pub fn image_tokens(&self, width: u32, height: u32) -> u32 {
        if width == 0 || height == 0 {
            return 0;
        }
        match *self {
            Self::Flat { tokens_per_image } => tokens_per_image,
            Self::PatchGrid {
                patch_size,
                max_tokens,
            } => {
                if patch_size == 0 {
                    return 0;
                }
                let patches = width
                    .div_ceil(patch_size)
                    .saturating_mul(height.div_ceil(patch_size));
                patches.min(max_tokens)
            }
            Self::Tiled {
                tile_size,
                tokens_per_tile,
                base_tokens,
                max_tiles,
            } => {
                if tile_size == 0 {
                    return base_tokens;
                }
                let tiles = width
                    .div_ceil(tile_size)
                    .saturating_mul(height.div_ceil(tile_size))
                    .min(max_tiles);
                base_tokens.saturating_add(tiles.saturating_mul(tokens_per_tile))
            }
        }
    }
}

/// Metadata about an inference response
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct InferenceMetadata {
    /// Billable work units consumed by the call, across every modality.
    pub units: BillableUnits,
    /// Inference latency (milliseconds)
    pub latency_ms: u64,
    /// Model version used
    pub model_version: Option<String>,
    /// Finish reason
    pub finish_reason: Option<String>,
}

/// Information about a model inference provider
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InferenceProvider {
    /// Provider address
    pub address: Address,
    /// Provider name
    pub name: String,
    /// OpenAI-compatible API endpoint URL (e.g., "http://192.168.1.10:8545/v1")
    pub endpoint_url: Option<String>,
    /// Models this provider serves
    pub models: Vec<String>,
    /// Provider capacity
    pub capacity: ProviderCapacity,
    /// Provider pricing
    pub pricing: crate::price_card::RateCard,
    /// The consensus reputation score of the provider's root, `0..=10_000`.
    pub reputation: u64,
    /// Total inferences served
    pub total_inferences: u64,
    /// Provider status
    pub status: ProviderStatus,
    /// Registration timestamp
    pub registered_at: Timestamp,
    /// Machine identity of the serving node, `did:tenzro:machine:...`. Its
    /// receipts and provenance manifests must be signed by the hardware
    /// identity key registered for this DID; routers resolve that key from
    /// the identity registry. `None` for a provider whose announcement named
    /// no machine identity: it cannot satisfy a signed-response request.
    #[serde(default)]
    pub machine_did: Option<String>,
}

impl InferenceProvider {
    /// Creates a new inference provider
    pub fn new(address: Address, name: String) -> Self {
        Self {
            address,
            name,
            endpoint_url: None,
            models: Vec::new(),
            capacity: ProviderCapacity::default(),
            pricing: crate::price_card::RateCard::default(),
            reputation: 0,
            total_inferences: 0,
            status: ProviderStatus::Pending,
            registered_at: Timestamp::now(),
            machine_did: None,
        }
    }

    /// Sets the provider's OpenAI-compatible API endpoint URL
    pub fn with_endpoint_url(mut self, url: impl Into<String>) -> Self {
        self.endpoint_url = Some(url.into());
        self
    }

    /// Sets the serving node's machine identity
    pub fn with_machine_did(mut self, machine_did: impl Into<String>) -> Self {
        self.machine_did = Some(machine_did.into());
        self
    }

    /// Adds a model to the provider
    pub fn add_model(&mut self, model_id: String) {
        if !self.models.contains(&model_id) {
            self.models.push(model_id);
        }
    }

    /// Checks if provider serves a model
    pub fn serves_model(&self, model_id: &str) -> bool {
        self.models.iter().any(|m| m == model_id)
    }
}

/// Provider capacity information
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProviderCapacity {
    /// Maximum concurrent requests
    pub max_concurrent_requests: u32,
    /// Current active requests
    pub active_requests: u32,
    /// Requests per second capacity
    pub requests_per_second: u32,
    /// Maximum batch size
    pub max_batch_size: u32,
    /// Multi-Token Prediction availability. Set by the provider in its
    /// announced capacity when its serving runtime has
    /// the target's paired drafter co-loaded (`HfModelEntry.drafter_id`
    /// with `mtp_kind == DraftMtp` or `Generic`). When true, the
    /// `InferenceRouter` may route MTP-eligible requests preferentially
    /// to this provider; when false, it falls back to standard
    /// autoregressive providers.
    #[serde(default)]
    pub mtp_enabled: bool,
    /// VRAM headroom (GB) the provider has reserved for the speculative
    /// drafter alongside the target. Unsloth measures ~2 GB extra for
    /// Gemma 4 MTP heads. `None` means the provider hasn't declared a
    /// drafter footprint, which is fine when `mtp_enabled = false`.
    #[serde(default)]
    pub drafter_vram_gb: Option<f32>,
    /// Whether this provider can produce TOPLOC inference commitments —
    /// per-token top-k logit records that a verifier holding the same
    /// weights can recheck with a single prefill. True for the built-in
    /// llama.cpp runtime (raw logits are readable in-process). Set
    /// automatically at registration — providers never configure it by
    /// hand.
    #[serde(default)]
    pub verifiable_inference: bool,
    /// MoE expert-shard declaration. When a provider can't fit an entire
    /// MoE model (e.g. Qwen 3.5 397B-A17B) on its hardware, it can host
    /// a subset of expert weights and serve as one peer in a
    /// decentralized expert-parallel dispatch. Empty `holdings` means
    /// the provider does not participate in MoE expert serving for any
    /// model and is treated as a full-model replica only.
    #[serde(default)]
    pub moe_holdings: Vec<MoeExpertHolding>,
    /// MoE-pipeline role this provider plays. `Replica` is the default —
    /// the provider holds the full model and serves single-peer
    /// inference. `Router` provides the gating-network step and fans
    /// out batched expert calls. `ExpertHolder` participates in the
    /// expert-shard pool. `PrefillDecode` runs both phases co-located
    /// (the centralized default). Providers can declare more than
    /// one role; the router picks the matching role per request.
    #[serde(default)]
    pub moe_roles: Vec<MoeProviderRole>,
    /// Whether this provider's MoE expert-compute path runs on a GPU
    /// (cuBLAS grouped GEMM on NVIDIA, or a cross-vendor WGSL compute
    /// shader on AMD / Apple / Intel) rather than the CPU floor. Set from
    /// the local `MoeExpertRuntime` compute-backend probe at declaration
    /// time. The router biases large token batches toward GPU-backed
    /// expert holders, since grouped-GEMM throughput dominates there; a
    /// CPU holder still serves correctly, just slower.
    #[serde(default)]
    pub moe_gpu: bool,
    /// Radix-tree summary of the prompt prefixes this provider holds warm in
    /// its KV cache. The router prefers the provider whose warm prefix best
    /// matches an incoming prompt (a warm prefix skips re-prefill, cutting
    /// time-to-first-token). Only prefix fingerprints ride the announcement —
    /// never KV bytes. Empty means the provider advertises no warm prefixes
    /// and competes on the other capacity/observed signals alone.
    #[serde(default)]
    pub prefix_cache: PrefixCacheSummary,
    /// Iroh endpoint id of this provider. Used by the MoE router to
    /// dispatch batched expert calls over QUIC directly to the holder
    /// peer without going through the OpenAI-compatible HTTP endpoint.
    /// Required when `moe_roles` includes `Router` or `ExpertHolder`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iroh_endpoint_id: Option<String>,
    /// Local-network cluster this node belongs to, if any. When set, the
    /// node is one machine in a provider-owned LAN cluster that serves a
    /// model too large for any single member by splitting it into a
    /// layer-wise pipeline across members (see [`LanCluster`]). `None`
    /// means the node serves standalone.
    ///
    /// Why layer-pipeline and not expert-parallel on the LAN: expert
    /// all-to-all dispatch is a latency-bound collective that needs an
    /// NVLink/RDMA-class interconnect; over commodity Ethernet it
    /// collapses. Splitting by contiguous layer range sends only the
    /// boundary activation between stages — point-to-point, tolerant of
    /// millisecond LAN latency. This is the pattern llama.cpp's RPC
    /// backend implements, and it is why MoE serves well
    /// over a LAN: each layer's experts stay co-resident on the stage
    /// that owns the layer, so there is no cross-machine all-to-all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lan_cluster: Option<LanCluster>,
    /// Self-declared hardware the provider serves inference on, detected
    /// locally via [`HardwareCapabilities::detect`] at announcement time.
    /// The router treats this as an *advertised* capability: it biases
    /// work toward higher-declared hardware (via
    /// [`HardwareCapabilities::class`]), but every advertised claim is
    /// gated on observed performance (success rate + measured latency),
    /// so a provider that overclaims is discounted back down as soon as
    /// its real serving latency and failure rate diverge from what the
    /// class implies. A provider whose hardware is undetected competes on
    /// observed metrics alone (neutral bias).
    #[serde(default)]
    pub hardware: HardwareCapabilities,
    /// Declared serving jurisdiction (attestation-bound locality claim).
    /// `None` means undeclared — the provider is excluded from any request
    /// that pins a jurisdiction (fail-closed; sovereignty never degrades
    /// silently).
    // NOT `skip_serializing_if`. This rides the gossip announcement, which is
    // bincode — a non-self-describing format with no field names on the wire.
    // A skipped field is simply absent while the decoder still reads one at
    // that position, so every following byte shifts. As the last field of
    // `AdvertisedCapacity`, omitting this one-byte `None` discriminant
    // desynchronised the entire `ProviderAnnouncementMessage` and surfaced
    // downstream as "tag for enum is not valid, found 64" — which took
    // provider discovery to zero on every node of the network at once.
    #[serde(default)]
    pub jurisdiction: Option<JurisdictionClaim>,
    /// The verification levels this provider can serve answers at.
    pub verification: Vec<crate::inference_verification::VerificationLevel>,
}

/// Compact advertised capacity envelope broadcast over the
/// provider-announcement gossip topic. This is the subset of
/// [`ProviderCapacity`] a discovery consumer needs to rank providers by
/// declared serving capacity and to build the MoE expert shard view,
/// without carrying the heavier LAN-cluster / hardware payload (the full
/// announcement already carries `hardware` separately). Every field here
/// is *advertised* by the provider; the network gates each claim on
/// observed serving metrics before trusting it.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AdvertisedCapacity {
    /// Maximum concurrent requests the provider will admit.
    pub max_concurrent_requests: u32,
    /// Active requests at announcement-build time.
    pub active_requests: u32,
    /// Declared sustained requests-per-second ceiling.
    pub requests_per_second: u32,
    /// Maximum batch size the serving runtime will coalesce.
    pub max_batch_size: u32,
    /// Whether the provider has a speculative drafter co-loaded (MTP).
    pub mtp_enabled: bool,
    /// Whether the provider can produce TOPLOC inference commitments.
    pub verifiable_inference: bool,
    /// MoE expert-shard holdings this provider serves. Router peers build
    /// their [`MoeExpertHolding`]-keyed shard view from these declarations,
    /// so a holding that never rides the announcement is unreachable for
    /// distributed dispatch.
    #[serde(default)]
    pub moe_holdings: Vec<MoeExpertHolding>,
    /// MoE-pipeline roles this provider declares (Router / ExpertHolder /
    /// Replica / prefill-decode variants).
    #[serde(default)]
    pub moe_roles: Vec<MoeProviderRole>,
    /// Whether this provider's MoE expert compute runs on a GPU backend.
    #[serde(default)]
    pub moe_gpu: bool,
    /// Radix-tree summary of the prompt prefixes this provider holds warm in
    /// its KV cache. Router peers score an incoming prompt against this to
    /// prefer a provider that can skip re-prefill. Fingerprints only, never
    /// KV bytes.
    #[serde(default)]
    pub prefix_cache: PrefixCacheSummary,
    /// Declared serving jurisdiction. Must ride the announcement so
    /// discovery consumers can rank providers for jurisdiction-pinned
    /// requests without a direct round-trip.
    // NOT `skip_serializing_if`. This rides the gossip announcement, which is
    // bincode — a non-self-describing format with no field names on the wire.
    // A skipped field is simply absent while the decoder still reads one at
    // that position, so every following byte shifts. As the last field of
    // `AdvertisedCapacity`, omitting this one-byte `None` discriminant
    // desynchronised the entire `ProviderAnnouncementMessage` and surfaced
    // downstream as "tag for enum is not valid, found 64" — which took
    // provider discovery to zero on every node of the network at once.
    #[serde(default)]
    pub jurisdiction: Option<JurisdictionClaim>,
    /// Models the provider holds on standby: weights staged in host memory,
    /// not serving, activated on a failover or a surge. A continuity session
    /// prefers such a node as its successor.
    pub standby_models: Vec<String>,
    /// The verification levels the provider says it serves at. A consumer
    /// checks each claim itself before routing on it, and every answer's
    /// evidence again on arrival.
    pub verification: Vec<crate::inference_verification::VerificationLevel>,
    /// TNZO per hour this provider charges to hold a session's checkpoint
    /// chain as its successor, from its own `[standby]` config — `0` while
    /// standby is disabled or free. Rides the announcement so a buyer can
    /// find and quote a reservation before any session names this node;
    /// the escrow a buyer funds against it is the source of truth for what
    /// is actually charged, this is only a discovery hint.
    #[serde(default, with = "crate::primitives::u128_serde")]
    pub standby_fee_per_hour: u128,
}

impl ProviderCapacity {
    /// Project the full capacity down to the compact advertised envelope
    /// carried on the announcement gossip.
    pub fn advertised(&self) -> AdvertisedCapacity {
        AdvertisedCapacity {
            max_concurrent_requests: self.max_concurrent_requests,
            active_requests: self.active_requests,
            requests_per_second: self.requests_per_second,
            max_batch_size: self.max_batch_size,
            mtp_enabled: self.mtp_enabled,
            verifiable_inference: self.verifiable_inference,
            moe_holdings: self.moe_holdings.clone(),
            moe_roles: self.moe_roles.clone(),
            moe_gpu: self.moe_gpu,
            prefix_cache: self.prefix_cache.clone(),
            jurisdiction: self.jurisdiction.clone(),
            standby_models: Vec::new(),
            verification: self.verification.clone(),
            standby_fee_per_hour: 0,
        }
    }
}

/// Provider's holding declaration for one MoE expert in one model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoeExpertHolding {
    /// Tenzro model id this holding covers.
    pub model_id: String,
    /// Transformer layer index.
    pub layer: u32,
    /// Expert index inside the layer's MoE block.
    pub expert: u32,
    /// Residency state — `Warm` (VRAM-resident), `Cold` (disk only),
    /// or `Evicting` (being unloaded). Schedulers prefer warm holdings.
    pub residency: MoeExpertResidency,
    /// Maximum tokens per second this provider commits to for this
    /// expert post-batch. `0` means "best effort" with no SLA.
    pub committed_tps: u32,
    /// Content-addressed `tenzro://blob/<hash>` URI the weights were loaded
    /// from. Carrying it on the announcement is what makes replication
    /// repair possible: a node that self-selects to hold an
    /// under-replicated expert reads the URI off any existing holder's
    /// declaration and fetches the bytes itself. `None` for experts loaded
    /// from an inline payload, which are unrepairable by other nodes.
    pub blob_uri: Option<String>,
}

/// A provider-owned cluster of machines on one local network that jointly
/// serve a model too large for any single member.
///
/// The cluster presents to the wider Tenzro network as a *single logical
/// provider* — one public [`Address`] and endpoint, owned by the elected
/// [`head`](LanCluster::head). The network neither sees nor routes to the
/// individual member machines; the head fans the layer-pipeline across
/// them internally over the LAN. A member may also be exposed on its own
/// Address (the "both" model) — that is independent of cluster membership
/// and governed by its own `InferenceProvider` registration.
///
/// Membership is the operator-signed list behind the cluster DID (see
/// [`crate::cluster_membership`]): members find each other by local-network
/// discovery and are admitted only when the list names them, and the
/// layer-range assignment is computed deterministically from each
/// member's declared VRAM (a bin-packing over `pipeline_stage`s). Every
/// member computes the identical assignment with no negotiation round —
/// the determinism is deliberate, so two members never disagree on who
/// owns which layers (a split assignment would corrupt the pipeline).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LanCluster {
    /// The cluster's DID (`did:tenzro:cluster:{id}`), derived from the
    /// operator's DID and the cluster name. The machines its verified
    /// membership list names form one logical provider.
    pub cluster_did: String,
    /// Address of the elected head — the member that owns the cluster's
    /// public registration and drives the pipeline. When this equals the
    /// node's own address, the node is the head. `None` during election
    /// (before a head is settled); members serve no traffic until a head
    /// is known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head: Option<Address>,
    /// LAN-reachable endpoint of this member, used only for intra-cluster
    /// pipeline traffic between members — never advertised to the wider
    /// network. Typically a private-range address (e.g. `10.x`, `192.168.x`,
    /// or an mDNS `.local` name) on the cluster's serving port.
    pub local_endpoint: String,
    /// The contiguous layer range this member serves in the pipeline, once
    /// assignment has settled. `None` until the cluster has computed the
    /// layer→member assignment (or for the head before members report
    /// their VRAM).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pipeline_stage: Option<PipelineStage>,
    /// VRAM this member contributes to the cluster, in GB. The layer
    /// assignment is a deterministic bin-packing weighted by this value,
    /// so a member with more VRAM is assigned proportionally more layers.
    pub vram_gb: f32,
}

/// One member's slice of a layer-wise pipeline: the half-open range of
/// transformer layers `[start_layer, end_layer)` it executes.
///
/// During decode, the stage receives the boundary activation from the
/// member owning the preceding range, runs its layers (all experts for
/// those layers stay co-resident here), and forwards the activation to
/// the next stage. The member owning the final range produces logits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineStage {
    /// First layer this stage owns (inclusive).
    pub start_layer: u32,
    /// One past the last layer this stage owns (exclusive).
    pub end_layer: u32,
}

impl PipelineStage {
    /// Number of layers this stage executes.
    pub fn layer_count(&self) -> u32 {
        self.end_layer.saturating_sub(self.start_layer)
    }

    /// Whether this stage owns the model's first layer range (the stage
    /// that accepts the embedded prompt).
    pub fn is_first(&self) -> bool {
        self.start_layer == 0
    }
}

/// MoE expert residency state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MoeExpertResidency {
    /// In VRAM, ready to dispatch.
    Warm,
    /// On disk / CPU RAM, eviction-eligible.
    Cold,
    /// Currently being unloaded.
    Evicting,
}

/// MoE pipeline roles a provider can play in distributed serving.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MoeProviderRole {
    /// Holds the full model; serves single-peer inference. The default.
    Replica,
    /// Runs the gating-network step and fans out batched expert calls
    /// to the appropriate expert holders.
    Router,
    /// Holds one or more experts declared in `moe_holdings`.
    ExpertHolder,
    /// Runs both prefill and decode phases co-located (the standard central
    /// pattern; the Tenzro fallback when only one provider can fit the
    /// model).
    PrefillDecode,
    /// Runs only the prefill phase; hands off KV cache to a decode
    /// peer over iroh. Pairs with `Decode`.
    Prefill,
    /// Runs only the decode phase; accepts KV cache from a prefill
    /// peer over iroh.
    Decode,
    /// Executes a contiguous layer range as one stage of a LAN
    /// layer-pipeline (see [`LanCluster`] / [`PipelineStage`]). Distinct
    /// from `ExpertHolder`: a pipeline stage owns *whole layers* (with all
    /// their experts co-resident) and exchanges only boundary activations
    /// with adjacent stages, rather than holding individual experts and
    /// participating in cross-machine all-to-all. This is the role members
    /// of a local-network cluster take.
    PipelineStage,
}

/// What a provider advertises about the prompt prefixes it holds warm.
///
/// Only a count rides the gossip. Which prefixes are warm is never published:
/// a public fingerprint of a prompt prefix lets anyone on the network confirm
/// a guess about another caller's prompt offline. A router learns whether a
/// provider holds a given prefix warm by probing that provider with
/// [`salted_prefix_digests`] computed under the caller's cache salt. Only a
/// party that already holds both the salt and the prompt can produce those
/// digests, and a provider only matches them against prefixes it recorded
/// under the same salt, so one caller's warm prefixes are invisible to every
/// other caller.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PrefixCacheSummary {
    /// Warm prefix runs of [`PREFIX_RUN_BYTES`] held across all callers. A
    /// router probes only providers that report some.
    pub warm_runs: u32,
}

/// Byte length of one prefix run. A prompt is chunked into whole runs of
/// this many bytes before digesting, so both sides of a probe agree on the
/// run boundaries.
pub const PREFIX_RUN_BYTES: usize = 512;

/// A keyed digest of one prefix run, chained onto every run before it.
pub type PrefixDigest = [u8; 16];

/// Domain tag separating prefix digests from every other SHA-256 use.
const PREFIX_DIGEST_DOMAIN: &[u8] = b"tenzro/prefix-run";

/// Chunk `prompt` into whole [`PREFIX_RUN_BYTES`] runs and return one digest
/// per run, root-first. Digest `i` is SHA-256 over the domain tag, the salt,
/// digest `i-1` and run `i`, truncated to 128 bits, so two prompts that
/// diverge at run `k` share digests `0..k` and differ from `k` on. A trailing
/// partial run is not digested.
///
/// The salt is what keeps these private: without it a digest cannot be
/// recomputed from a guessed prompt.
pub fn salted_prefix_digests(salt: &[u8; 32], prompt: &[u8]) -> Vec<PrefixDigest> {
    use sha2::{Digest, Sha256};
    let mut out = Vec::with_capacity(prompt.len() / PREFIX_RUN_BYTES);
    let mut prev: PrefixDigest = [0u8; 16];
    for run in prompt.chunks(PREFIX_RUN_BYTES) {
        if run.len() < PREFIX_RUN_BYTES {
            break;
        }
        let mut h = Sha256::new();
        h.update(PREFIX_DIGEST_DOMAIN);
        h.update(salt);
        h.update(prev);
        h.update(run);
        let full = h.finalize();
        prev.copy_from_slice(&full[..16]);
        out.push(prev);
    }
    out
}

impl Default for ProviderCapacity {
    fn default() -> Self {
        Self {
            max_concurrent_requests: 10,
            active_requests: 0,
            requests_per_second: 100,
            max_batch_size: 1,
            mtp_enabled: false,
            verifiable_inference: false,
            drafter_vram_gb: None,
            moe_holdings: Vec::new(),
            moe_roles: Vec::new(),
            moe_gpu: false,
            prefix_cache: PrefixCacheSummary::default(),
            iroh_endpoint_id: None,
            lan_cluster: None,
            hardware: HardwareCapabilities::default(),
            jurisdiction: None,
            verification: Vec::new(),
        }
    }
}

impl ProviderCapacity {
    /// Checks if provider has capacity for a new request
    pub fn has_capacity(&self) -> bool {
        self.active_requests < self.max_concurrent_requests
    }

    /// Returns the utilization percentage (0-100)
    pub fn utilization(&self) -> u8 {
        if self.max_concurrent_requests == 0 {
            0
        } else {
            ((self.active_requests as f64 / self.max_concurrent_requests as f64) * 100.0) as u8
        }
    }
}

/// Provider operational status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProviderStatus {
    /// Registration pending
    Pending,
    /// Active and accepting requests
    Active,
    /// Temporarily inactive
    Inactive,
    /// Suspended
    Suspended,
}

// === Model Service Instances ===

/// A served model instance on the Tenzro network.
///
/// Each model that is actively served (locally or by a remote provider)
/// gets a unique UUID-based service instance with both API and MCP endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelServiceInstance {
    /// Unique service instance ID (UUID v4)
    pub instance_id: String,
    /// Catalog model ID (e.g., "qwen3-8b")
    pub model_id: String,
    /// Human-readable model name
    pub model_name: String,
    /// Provider's network address
    pub provider_address: Address,
    /// Human-readable provider name
    pub provider_name: String,
    /// Whether the model is local or on a remote network provider
    pub location: ModelLocation,
    /// MCP server endpoint (e.g., "http://host:3001/mcp")
    pub mcp_endpoint: String,
    /// Current service status
    pub status: ServiceStatus,
    /// Model parameters (e.g., "8B")
    pub parameters: String,
    /// Pricing configuration
    pub pricing: crate::price_card::RateCard,
    /// Timestamp when this instance was registered
    pub created_at: u64,
    /// Last time this endpoint was confirmed alive (Unix timestamp).
    /// Network endpoints expire after 5 minutes without heartbeat.
    #[serde(default)]
    pub last_seen: u64,
    /// Current load information (updated dynamically, only for local models)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_info: Option<ModelLoadInfo>,
    /// iroh EndpointId of the serving node, hex-encoded: the only address a
    /// remote model is reached at, resolved through the signed endpoint
    /// records. Empty for local services.
    #[serde(default)]
    pub iroh_endpoint_id: String,
}

/// Whether a model is served locally or by a remote network provider
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModelLocation {
    /// Served on this node
    Local,
    /// Served by a remote provider on the Tenzro network
    Network,
}

impl std::fmt::Display for ModelLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Local => write!(f, "local"),
            Self::Network => write!(f, "network"),
        }
    }
}

/// Operational status of a model service instance
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceStatus {
    /// Online and accepting requests
    Online,
    /// Offline or unreachable
    Offline,
    /// Degraded performance
    Degraded,
}

impl std::fmt::Display for ServiceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Online => write!(f, "online"),
            Self::Offline => write!(f, "offline"),
            Self::Degraded => write!(f, "degraded"),
        }
    }
}

/// Dynamic load information for a model service instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelLoadInfo {
    /// Number of requests currently being processed or queued
    pub active_requests: u32,
    /// Maximum concurrent requests this instance can handle
    pub max_concurrent: u32,
    /// Utilization percentage (0-100)
    pub utilization_percent: u8,
    /// Human-readable load level
    pub load_level: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Rich chat shape types
//
// These types support the "rich" call shape of `tenzro_chat` — multi-turn
// conversations, system prompts, tool calls, vision input, and structured
// assistant responses built from content blocks. The simple call shape
// (single `message` string) does not use these types and routes through
// `ModelChatMessage` in `tenzro-model::runtime`.
//
// Schema mirrors Anthropic's Messages API content-block format. See
// `docs/chat-api.md` for the public RPC contract.
// ─────────────────────────────────────────────────────────────────────────────

/// A content block — the atomic unit of structured chat content.
///
/// Tagged externally on `type` for wire compatibility with Anthropic's
/// Messages API (so SDKs that already speak that schema work unchanged).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentBlock {
    /// Plain text content. Both directions (user input, assistant output).
    Text {
        text: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cache_control: Option<CacheControl>,
    },
    /// Extended-thinking trace. Assistant-only.
    Thinking { thinking: String },
    /// A tool invocation by the assistant. Assistant-only.
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
    },
    /// A tool execution result returned by the client. User-only.
    ToolResult {
        tool_use_id: String,
        /// Result content — either a plain string or a list of blocks
        /// (typically `text` blocks, or an `image` for vision tools).
        content: ToolResultContent,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        is_error: Option<bool>,
    },
    /// Vision input. User-only.
    Image { source: ImageSource },
}

/// Cache control marker — pins the prefix up to and including this block
/// as a cache breakpoint. Identical-prefix subsequent calls reuse the KV
/// cache and are billed at a discounted rate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CacheControl {
    /// Ephemeral cache (≤5 min lifetime).
    Ephemeral,
}

/// Tool-result payload. Either a single string (the common case) or a list
/// of content blocks (when the tool returns structured or visual content).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ToolResultContent {
    Text(String),
    Blocks(Vec<ContentBlock>),
}

/// Image source — only base64 inline for now. URL sources may be added later.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ImageSource {
    Base64 { media_type: String, data: String },
}

/// A message in the rich shape. `content` is either a plain string (which
/// the handler normalizes to a single `text` block) or an explicit array
/// of blocks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RichChatMessage {
    /// `"user"` or `"assistant"`. The simple/rich routing keeps the system
    /// prompt out of the messages array — see `RichChatRequest::system`.
    pub role: String,
    pub content: MessageContent,
}

/// Message content — string or block array. The wire format permits either
/// for user messages; assistant messages are always emitted as block arrays.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MessageContent {
    Text(String),
    Blocks(Vec<ContentBlock>),
}

impl MessageContent {
    /// Normalizes content to a vec of blocks. A plain string becomes a
    /// single `text` block.
    pub fn into_blocks(self) -> Vec<ContentBlock> {
        match self {
            MessageContent::Text(s) => vec![ContentBlock::Text {
                text: s,
                cache_control: None,
            }],
            MessageContent::Blocks(b) => b,
        }
    }

    /// Borrows content as a slice of blocks, allocating only when the
    /// content is a plain string. Useful for read-only passes (token
    /// counting, validation).
    pub fn as_blocks(&self) -> std::borrow::Cow<'_, [ContentBlock]> {
        match self {
            MessageContent::Text(s) => std::borrow::Cow::Owned(vec![ContentBlock::Text {
                text: s.clone(),
                cache_control: None,
            }]),
            MessageContent::Blocks(b) => std::borrow::Cow::Borrowed(b),
        }
    }
}

impl ContentBlock {
    /// Total byte length of the text-bearing payload of this block,
    /// including inline image data. Used to bound request size before a
    /// request reaches a provider's context window.
    pub fn payload_len(&self) -> usize {
        match self {
            ContentBlock::Text { text, .. } => text.len(),
            ContentBlock::Thinking { thinking } => thinking.len(),
            ContentBlock::ToolUse { name, input, .. } => name.len() + input.to_string().len(),
            ContentBlock::ToolResult { content, .. } => match content {
                ToolResultContent::Text(s) => s.len(),
                ToolResultContent::Blocks(bs) => bs.iter().map(ContentBlock::payload_len).sum(),
            },
            ContentBlock::Image { source } => match source {
                ImageSource::Base64 { data, .. } => data.len(),
            },
        }
    }
}

impl RichChatMessage {
    /// Total byte length of this message's content payload across all blocks.
    pub fn payload_len(&self) -> usize {
        self.content
            .as_blocks()
            .iter()
            .map(ContentBlock::payload_len)
            .sum()
    }
}

/// A tool the model may invoke. The model emits `ContentBlock::ToolUse`
/// blocks whose `input` validates against `input_schema`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolSchema {
    /// Tool name. Must match `^[a-zA-Z0-9_-]{1,64}$`.
    pub name: String,
    pub description: String,
    /// JSON Schema (draft 2020-12) describing the tool's input.
    pub input_schema: serde_json::Value,
}

/// Reasoning effort budget for extended-thinking models.
///
/// The wire vocabulary is the union across served families; which levels a
/// given model actually accepts, and the chat-template variable they are
/// rendered into, is decided per family by the model catalog's effort policy.
/// A level a model does not support is dropped there rather than rejected
/// here, so this enum stays a transport type and not a per-model constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ReasoningEffort {
    Low,
    #[default]
    Medium,
    High,
    /// Above `High`. Qwen 3.8 treats this as its default and folds `high` into
    /// it; Muse-Glimmer exposes it as the top of a four-level ladder.
    #[serde(rename = "xhigh")]
    XHigh,
}

impl ReasoningEffort {
    /// Lowercase wire form, matching the serde representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::XHigh => "xhigh",
        }
    }
}

impl std::fmt::Display for ReasoningEffort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// System-prompt content — either a plain string or a block array (so
/// `cache_control` can be applied to system text).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SystemPrompt {
    Text(String),
    Blocks(Vec<ContentBlock>),
}

impl SystemPrompt {
    /// Returns the system prompt as a single concatenated string, suitable
    /// for chat templates that take a flat system field.
    pub fn as_text(&self) -> String {
        match self {
            SystemPrompt::Text(s) => s.clone(),
            SystemPrompt::Blocks(blocks) => blocks
                .iter()
                .filter_map(|b| match b {
                    ContentBlock::Text { text, .. } => Some(text.as_str()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join(""),
        }
    }
}

/// Why the assistant stopped generating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    /// Model finished naturally.
    EndTurn,
    /// Hit the `max_tokens` limit.
    MaxTokens,
    /// Hit a sequence in `stop_sequences`.
    StopSequence,
    /// Model emitted one or more `tool_use` blocks; the client is expected
    /// to execute them and return `tool_result` blocks in the next turn.
    ToolUse,
}

/// Token usage and cache metrics on a rich-shape response.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RichUsage {
    pub input_tokens: u32,
    pub output_tokens: u32,
    #[serde(default)]
    pub cache_creation_input_tokens: u32,
    #[serde(default)]
    pub cache_read_input_tokens: u32,
}

#[cfg(test)]
mod rich_chat_tests {
    use super::*;

    #[test]
    fn text_block_roundtrip() {
        let b = ContentBlock::Text {
            text: "hello".to_string(),
            cache_control: None,
        };
        let json = serde_json::to_string(&b).unwrap();
        assert_eq!(json, r#"{"type":"text","text":"hello"}"#);
        let decoded: ContentBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, b);
    }

    #[test]
    fn thinking_block_roundtrip() {
        let b = ContentBlock::Thinking {
            thinking: "let me check".to_string(),
        };
        let json = serde_json::to_string(&b).unwrap();
        assert!(json.contains(r#""type":"thinking""#));
        let decoded: ContentBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, b);
    }

    #[test]
    fn tool_use_block_roundtrip() {
        let b = ContentBlock::ToolUse {
            id: "tu_01".to_string(),
            name: "get_price".to_string(),
            input: serde_json::json!({"pair": "TNZO/USD"}),
        };
        let json = serde_json::to_string(&b).unwrap();
        assert!(json.contains(r#""type":"tool_use""#));
        let decoded: ContentBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, b);
    }

    #[test]
    fn tool_result_string_content() {
        let b = ContentBlock::ToolResult {
            tool_use_id: "tu_01".to_string(),
            content: ToolResultContent::Text("0.42".to_string()),
            is_error: None,
        };
        let json = serde_json::to_string(&b).unwrap();
        let decoded: ContentBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, b);
    }

    #[test]
    fn message_content_string_normalizes_to_text_block() {
        let mc = MessageContent::Text("hello".to_string());
        let blocks = mc.into_blocks();
        assert_eq!(blocks.len(), 1);
        match &blocks[0] {
            ContentBlock::Text { text, .. } => assert_eq!(text, "hello"),
            _ => panic!("expected text block"),
        }
    }

    #[test]
    fn message_content_accepts_string_or_blocks() {
        let s: MessageContent = serde_json::from_str(r#""hello""#).unwrap();
        assert!(matches!(s, MessageContent::Text(_)));
        let b: MessageContent = serde_json::from_str(r#"[{"type":"text","text":"hi"}]"#).unwrap();
        assert!(matches!(b, MessageContent::Blocks(_)));
    }

    #[test]
    fn stop_reason_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&StopReason::EndTurn).unwrap(),
            r#""end_turn""#
        );
        assert_eq!(
            serde_json::to_string(&StopReason::ToolUse).unwrap(),
            r#""tool_use""#
        );
        assert_eq!(
            serde_json::to_string(&StopReason::MaxTokens).unwrap(),
            r#""max_tokens""#
        );
    }

    #[test]
    fn reasoning_effort_serializes_lowercase() {
        assert_eq!(
            serde_json::to_string(&ReasoningEffort::Low).unwrap(),
            r#""low""#
        );
        assert_eq!(
            serde_json::to_string(&ReasoningEffort::High).unwrap(),
            r#""high""#
        );
    }

    #[test]
    fn system_prompt_blocks_concatenate() {
        let sp = SystemPrompt::Blocks(vec![
            ContentBlock::Text {
                text: "you are ".to_string(),
                cache_control: None,
            },
            ContentBlock::Text {
                text: "helpful".to_string(),
                cache_control: Some(CacheControl::Ephemeral),
            },
        ]);
        assert_eq!(sp.as_text(), "you are helpful");
    }

    #[test]
    fn full_rich_request_roundtrip() {
        let json = r#"{
            "role": "user",
            "content": [
                {"type": "text", "text": "What is TNZO trading at?"}
            ]
        }"#;
        let msg: RichChatMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.role, "user");
        assert_eq!(msg.content.as_blocks().len(), 1);
    }

    #[test]
    fn assistant_with_thinking_and_tool_use() {
        let json = r#"{
            "role": "assistant",
            "content": [
                {"type": "thinking", "thinking": "I should query the price oracle."},
                {"type": "tool_use", "id": "tu_01", "name": "get_price", "input": {"pair": "TNZO/USD"}}
            ]
        }"#;
        let msg: RichChatMessage = serde_json::from_str(json).unwrap();
        let blocks = msg.content.as_blocks();
        assert_eq!(blocks.len(), 2);
        assert!(matches!(&blocks[0], ContentBlock::Thinking { .. }));
        assert!(matches!(&blocks[1], ContentBlock::ToolUse { .. }));
    }
}

#[cfg(test)]
mod moe_tests {
    use super::*;

    #[test]
    fn moe_metadata_mixtral_8x7b() {
        // Mixtral 8x7B: 8 routed experts, top-2 routing, no shared experts.
        let moe = MoeMetadata::new(8, 2, MoeRoutingStrategy::TopK)
            .with_params_per_expert_x10(70) // 7.0B per expert
            .with_attention_type("gqa");
        assert_eq!(moe.num_experts, 8);
        assert_eq!(moe.experts_per_token, 2);
        assert_eq!(moe.shared_experts, 0);
        assert_eq!(moe.active_experts_per_token(), 2);
        assert_eq!(moe.total_routed_params_x10(), Some(560)); // 56.0B total
        assert_eq!(moe.active_params_per_token_x10(), Some(140)); // 14.0B active
    }

    #[test]
    fn moe_metadata_deepseek_shared_experts() {
        // DeepSeek-V2-style: routed + shared (always-on) experts.
        let moe = MoeMetadata::new(64, 6, MoeRoutingStrategy::TopK)
            .with_shared_experts(2)
            .with_params_per_expert_x10(3); // 0.3B per expert
        assert_eq!(moe.active_experts_per_token(), 8); // 6 routed + 2 shared
        assert_eq!(moe.active_params_per_token_x10(), Some(24)); // 2.4B active
    }

    #[test]
    fn moe_metadata_specialization_roundtrip() {
        let labels = vec![
            "math".to_string(),
            "code".to_string(),
            "reasoning".to_string(),
        ];
        let moe = MoeMetadata::new(3, 1, MoeRoutingStrategy::Switch)
            .with_expert_specialization(labels.clone());
        assert_eq!(moe.expert_specialization.as_ref(), Some(&labels));
    }

    #[test]
    fn model_info_moe_wiring() {
        let info = ModelInfo::new(
            "mixtral-8x7b".to_string(),
            "Mixtral".to_string(),
            "0.1".to_string(),
            ModelModality::Text,
            Address::zero(),
        );
        assert!(!info.is_moe());
        let info = info.with_moe(MoeMetadata::new(8, 2, MoeRoutingStrategy::TopK));
        assert!(info.is_moe());
        assert_eq!(info.moe.as_ref().unwrap().num_experts, 8);
    }

    #[test]
    fn moe_metadata_serde_json_omits_when_absent() {
        let info = ModelInfo::new(
            "dense-7b".to_string(),
            "Dense".to_string(),
            "0.1".to_string(),
            ModelModality::Text,
            Address::zero(),
        );
        let json = serde_json::to_string(&info).unwrap();
        // `moe: None` is skipped via skip_serializing_if.
        assert!(!json.contains("\"moe\""));
    }

    #[test]
    fn moe_metadata_serde_roundtrip() {
        let info = ModelInfo::new(
            "mixtral-8x7b".to_string(),
            "Mixtral".to_string(),
            "0.1".to_string(),
            ModelModality::Text,
            Address::zero(),
        )
        .with_moe(
            MoeMetadata::new(8, 2, MoeRoutingStrategy::TopK)
                .with_params_per_expert_x10(70)
                .with_attention_type("gqa")
                .with_capacity_factor_x100(125),
        );
        let json = serde_json::to_string(&info).unwrap();
        let decoded: ModelInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.moe, info.moe);
    }
}
