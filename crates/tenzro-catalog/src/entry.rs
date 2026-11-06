//! One catalog entry: a model as its publisher describes it.
//!
//! An entry names the engine family that runs the model and carries the
//! engine-specific description ([`ModelSpec`]), the licence, whether the
//! weights are gated at their origin, and every file a node fetches for the
//! model with the SHA-256 its bytes must have ([`Component`]). The hash, not
//! the origin, identifies a file: bytes fetched from the Hugging Face Hub or
//! from a peer's blob store are accepted only when they hash to it. Gated
//! weights are never fetched from the Hub; nodes whose operators accepted
//! their licence pass them between themselves by content hash.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    EmbedModelEntry, HfModelEntry, LicenseTier, MediaGenModelEntry, OmniModelEntry, OnnxAudioEntry,
    OnnxDetectionEntry, OnnxForecastEntry, OnnxSegmentationEntry, OnnxTextEmbeddingEntry,
    OnnxTextSegmentationEntry, OnnxVideoEntry, OnnxVisionEntry, TtsModelEntry,
};

/// The engine family that runs a model, with that engine's description of it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "engine", content = "spec", rename_all = "kebab-case")]
pub enum ModelSpec {
    /// A GGUF language model served by the llama.cpp engine.
    Gguf(HfModelEntry),
    /// A GGUF cross-encoder reranker served by the Praecise engine.
    Rerank(HfModelEntry),
    /// A GGUF decision model (typed questions answered in one forward pass)
    /// served by the Praecise engine.
    Decision(HfModelEntry),
    OnnxVision(OnnxVisionEntry),
    OnnxForecast(OnnxForecastEntry),
    OnnxTextEmbedding(OnnxTextEmbeddingEntry),
    /// A GGUF pooled embedder served by the Praecise engine.
    Embed(EmbedModelEntry),
    OnnxSegmentation(OnnxSegmentationEntry),
    OnnxTextSegmentation(OnnxTextSegmentationEntry),
    OnnxDetection(OnnxDetectionEntry),
    OnnxAudio(OnnxAudioEntry),
    /// Speech synthesis, served by the Praecise speech engine.
    Tts(TtsModelEntry),
    /// Spoken replies: a reading model and its talker.
    Omni(OmniModelEntry),
    OnnxVideo(OnnxVideoEntry),
    /// Image, video and 3D generation, in the node's process on the Praecise
    /// diffusion engine.
    MediaGen(MediaGenModelEntry),
}

/// What runs a catalog entry on this release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Loader {
    /// The Praecise engine, from a GGUF whose `general.architecture` is one
    /// of these.
    Engine(&'static [&'static str]),
    /// A Praecise media pipeline, pinned to the engine revision it runs on.
    Media,
    /// The ONNX runtime inside the node.
    Onnx,
    /// A media entry the node refuses at serve time as planned.
    Planned,
    /// Nothing loads the entry; the reason says why.
    Missing(String),
}

impl ModelSpec {
    /// What loads this entry. A GGUF entry resolves through its
    /// architecture label, an embedder and a speech model through their
    /// family; [`Loader::Missing`] means no engine on this release loads it.
    pub fn loader(&self) -> Loader {
        match self {
            ModelSpec::Gguf(e) | ModelSpec::Rerank(e) | ModelSpec::Decision(e) => {
                match e.architecture.engine_architectures() {
                    Ok(archs) => Loader::Engine(archs),
                    Err(why) => Loader::Missing(format!("architecture {}: {why}", e.architecture)),
                }
            }
            ModelSpec::Embed(e) => match e.family.as_str() {
                "qwen3-vl-embedding" => Loader::Engine(&["qwen3vl"]),
                f => Loader::Missing(format!("embedder family {f}: no engine loader")),
            },
            ModelSpec::Tts(e) => match e.family.as_str() {
                "qwen3-tts" => Loader::Engine(&["qwen3tts"]),
                f => Loader::Missing(format!("speech family {f}: no engine loader")),
            },
            ModelSpec::Omni(e) => match e.family.as_str() {
                "qwen3-omni" => Loader::Engine(&["qwen3vlmoe", "qwen3omnitalker"]),
                f => Loader::Missing(format!("omni family {f}: no engine loader")),
            },
            ModelSpec::MediaGen(m) => match m.status {
                crate::MediaGenStatus::Native => Loader::Media,
                crate::MediaGenStatus::Planned => Loader::Planned,
            },
            ModelSpec::OnnxVision(_)
            | ModelSpec::OnnxForecast(_)
            | ModelSpec::OnnxTextEmbedding(_)
            | ModelSpec::OnnxSegmentation(_)
            | ModelSpec::OnnxTextSegmentation(_)
            | ModelSpec::OnnxDetection(_)
            | ModelSpec::OnnxAudio(_)
            | ModelSpec::OnnxVideo(_) => Loader::Onnx,
        }
    }

    pub fn id(&self) -> &str {
        match self {
            ModelSpec::Gguf(e) | ModelSpec::Rerank(e) | ModelSpec::Decision(e) => &e.id,
            ModelSpec::OnnxVision(e) => &e.id,
            ModelSpec::OnnxForecast(e) => &e.id,
            ModelSpec::OnnxTextEmbedding(e) => &e.id,
            ModelSpec::Embed(e) => &e.id,
            ModelSpec::OnnxSegmentation(e) => &e.id,
            ModelSpec::OnnxTextSegmentation(e) => &e.id,
            ModelSpec::OnnxDetection(e) => &e.id,
            ModelSpec::OnnxAudio(e) => &e.id,
            ModelSpec::Tts(e) => &e.id,
            ModelSpec::Omni(e) => &e.id,
            ModelSpec::OnnxVideo(e) => &e.id,
            ModelSpec::MediaGen(e) => &e.id,
        }
    }

    /// The engine family, as it appears in the entry's `engine` field.
    pub fn engine(&self) -> &'static str {
        match self {
            ModelSpec::Gguf(_) => "gguf",
            ModelSpec::Rerank(_) => "rerank",
            ModelSpec::Decision(_) => "decision",
            ModelSpec::OnnxVision(_) => "onnx-vision",
            ModelSpec::OnnxForecast(_) => "onnx-forecast",
            ModelSpec::OnnxTextEmbedding(_) => "onnx-text-embedding",
            ModelSpec::Embed(_) => "embed",
            ModelSpec::OnnxSegmentation(_) => "onnx-segmentation",
            ModelSpec::OnnxTextSegmentation(_) => "onnx-text-segmentation",
            ModelSpec::OnnxDetection(_) => "onnx-detection",
            ModelSpec::OnnxAudio(_) => "onnx-audio",
            ModelSpec::Tts(_) => "tts",
            ModelSpec::Omni(_) => "omni",
            ModelSpec::OnnxVideo(_) => "onnx-video",
            ModelSpec::MediaGen(_) => "media-gen",
        }
    }

    /// The registered units ([`tenzro_types::meter::genesis_units`]) a call to
    /// this engine is metered on, which a provider's price card must price
    /// for the call to be charged. Derived from the engine, which is what
    /// meters the call, not declared by the publisher. A forecast is charged per point (series × horizon step,
    /// every quantile at that step included), a reranker per (query, document)
    /// pair, and an embedding per input token; none of them is charged on
    /// completion tokens.
    pub fn billed_on(&self) -> &'static [&'static str] {
        match self {
            ModelSpec::Gguf(_) => &[
                "input_tokens",
                "output_tokens",
                "cached_read_tokens",
                "cached_write_tokens",
                "image_tokens",
            ],
            ModelSpec::Rerank(_) => &["rerank_pairs"],
            ModelSpec::Decision(_) => &["decision_questions"],
            ModelSpec::OnnxForecast(_) => &["forecast_points"],
            ModelSpec::OnnxTextEmbedding(_) | ModelSpec::Embed(_) => &["input_tokens"],
            ModelSpec::OnnxVision(_) => &["image_tokens"],
            ModelSpec::OnnxSegmentation(_)
            | ModelSpec::OnnxTextSegmentation(_)
            | ModelSpec::OnnxDetection(_) => &["image_tokens", "output_tokens"],
            ModelSpec::OnnxAudio(_) => &["audio_ms"],
            ModelSpec::Tts(_) => &["characters", "audio_out_ms"],
            ModelSpec::Omni(_) => &["input_tokens", "output_tokens", "audio_ms", "audio_out_ms"],
            ModelSpec::OnnxVideo(_) => &["video_ms", "frames"],
            ModelSpec::MediaGen(_) => &["pixel_steps"],
        }
    }

    pub fn name(&self) -> &str {
        match self {
            ModelSpec::Gguf(e) | ModelSpec::Rerank(e) | ModelSpec::Decision(e) => &e.name,
            ModelSpec::OnnxVision(e) => &e.name,
            ModelSpec::OnnxForecast(e) => &e.name,
            ModelSpec::OnnxTextEmbedding(e) => &e.name,
            ModelSpec::Embed(e) => &e.name,
            ModelSpec::OnnxSegmentation(e) => &e.name,
            ModelSpec::OnnxTextSegmentation(e) => &e.name,
            ModelSpec::OnnxDetection(e) => &e.name,
            ModelSpec::OnnxAudio(e) => &e.name,
            ModelSpec::Tts(e) => &e.name,
            ModelSpec::Omni(e) => &e.name,
            ModelSpec::OnnxVideo(e) => &e.name,
            ModelSpec::MediaGen(e) => &e.name,
        }
    }
}

/// The licence the weights are published under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Licence {
    /// The licence as the model's origin names it.
    pub name: String,
    /// Stable id of a custom licence, matched against the operator's
    /// `--accept-license` list and the territorial grants.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub tier: LicenseTier,
    /// The conditions the licence attaches to commercial use, as its text
    /// states them: revenue thresholds, required authorizations, display
    /// duties, territorial limits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<String>,
    /// Further licences that cover parts of the weights (a text encoder
    /// published under its own terms, say). The fields above are the
    /// licence of the checkpoint itself; serving the model is bound by all.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub components: Vec<ComponentLicence>,
}

/// The licence of one part of a model's weights.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentLicence {
    /// The part of the weights the licence covers.
    pub covers: String,
    /// The licence as the part's origin names it.
    pub name: String,
    /// Stable id of a custom licence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub tier: LicenseTier,
    /// The conditions the licence attaches to commercial use.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<String>,
}

/// One licence an entry is bound by, the checkpoint's or a component's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LicencePart<'a> {
    /// The part of the weights it covers; `None` for the checkpoint's own.
    pub covers: Option<&'a str>,
    pub name: &'a str,
    pub id: Option<&'a str>,
    pub tier: LicenseTier,
    pub conditions: Option<&'a str>,
}

impl Licence {
    /// Every licence the weights are bound by: the checkpoint's first, then
    /// each component's.
    pub fn parts(&self) -> Vec<LicencePart<'_>> {
        std::iter::once(LicencePart {
            covers: None,
            name: &self.name,
            id: self.id.as_deref(),
            tier: self.tier,
            conditions: self.conditions.as_deref(),
        })
        .chain(self.components.iter().map(|c| LicencePart {
            covers: Some(&c.covers),
            name: &c.name,
            id: c.id.as_deref(),
            tier: c.tier,
            conditions: c.conditions.as_deref(),
        }))
        .collect()
    }

    /// The tier serving the model falls under: the most restrictive of every
    /// licence it is bound by.
    pub fn effective_tier(&self) -> LicenseTier {
        self.parts()
            .iter()
            .map(|p| p.tier)
            .max()
            .unwrap_or(self.tier)
    }

    /// The licence part that sets [`Self::effective_tier`] (the first such).
    pub fn governing(&self) -> LicencePart<'_> {
        let tier = self.effective_tier();
        self.parts()
            .into_iter()
            .find(|p| p.tier == tier)
            .expect("the effective tier is one part's tier")
    }

    /// The conditions of every licence, one line each, each named by its
    /// licence (and the part it covers); `None` when no licence states any.
    pub fn all_conditions(&self) -> Option<String> {
        let lines: Vec<String> = self
            .parts()
            .iter()
            .filter_map(|p| {
                p.conditions.map(|c| match p.covers {
                    Some(part) => format!("{} ({part}): {c}", p.name),
                    None if self.components.is_empty() => c.to_string(),
                    None => format!("{}: {c}", p.name),
                })
            })
            .collect();
        (!lines.is_empty()).then(|| lines.join("\n"))
    }
}

/// One file a node fetches for a model, from a fixed origin, and the SHA-256
/// its bytes must have wherever they come from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Component {
    /// Repository the file belongs to, `owner/name`. For a hub file it is the
    /// repository on the Hugging Face Hub; for a network file it is the
    /// publisher's name for the artifact.
    pub repo: String,
    /// Path of the file within the repository.
    pub path: String,
    /// Where the bytes come from.
    #[serde(flatten)]
    pub source: Source,
    /// Size in bytes.
    pub size: u64,
    /// Lowercase hex SHA-256 of the file's bytes.
    pub sha256: String,
    /// Where the file sits in the checkpoint directory a pipeline loads,
    /// when that differs from its path in the repository (a release that
    /// ships a transformer or an autoencoder as one file beside other
    /// parts). `None` places it at its path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
}

/// Where a component's bytes are fetched from.
///
/// A hub file is read from its repository at a fixed commit (and may also be
/// served by peers). A network file has no hub copy: storage providers hold it
/// at its BLAKE3 content address, a node fetches it by that address alone and
/// keeps it only if it hashes to the pinned SHA-256. A network file is built,
/// so it names the checkpoint it was built from and the in-tree recipe that
/// rebuilds it byte for byte.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum Source {
    Network {
        /// Lowercase hex BLAKE3 of the file's bytes: its content address.
        blake3: String,
        /// The upstream checkpoint, at a fixed commit, the file is built from.
        built_from: SourceCheckpoint,
        /// Repository-relative path of the script that builds the file from
        /// `built_from`; the script pins its own toolchain.
        recipe: String,
    },
    Hub {
        /// Git commit the file is fetched at.
        revision: String,
    },
}

impl Component {
    /// The file's path in the checkpoint directory a pipeline loads.
    pub fn view_path(&self) -> &str {
        self.at.as_deref().unwrap_or(&self.path)
    }

    /// The commit a hub file is fetched at; `None` for a network file.
    pub fn revision(&self) -> Option<&str> {
        match &self.source {
            Source::Hub { revision } => Some(revision),
            Source::Network { .. } => None,
        }
    }

    /// The BLAKE3 content address of a network file; `None` for a hub file.
    pub fn network_blake3(&self) -> Option<&str> {
        match &self.source {
            Source::Network { blake3, .. } => Some(blake3),
            Source::Hub { .. } => None,
        }
    }
}

/// The unquantised checkpoint a Mixture-of-Experts entry's experts are
/// extracted from, read at a fixed commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceCheckpoint {
    pub repo: String,
    pub revision: String,
}

/// Parts of another catalog entry this entry loads alongside its own files.
///
/// The parts are fetched from the other entry's pinned components into that
/// entry's own directory, so one copy on disk serves both models.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryDependency {
    /// Id of the entry whose files are loaded.
    pub entry: String,
    /// Parts of that entry's checkpoint that are loaded: top-level
    /// directories (`text_encoder`, `vae`, ...) or single files
    /// (`transformer/config.json`).
    pub parts: Vec<String>,
}

/// One file of the checkpoint directory an entry's pipeline loads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ViewFile<'a> {
    /// Path of the file in the checkpoint directory.
    pub at: &'a str,
    /// Id of the entry the file is pinned by: the entry itself, or one it
    /// requires (whose fetched copy is shared).
    pub entry: &'a str,
    /// The pinned file.
    pub component: &'a Component,
}

/// Whether a relative path is plain: non-empty segments, none of them `.`
/// or `..`.
fn plain_path(p: &str) -> bool {
    !p.is_empty()
        && !p.starts_with('/')
        && p.split('/').all(|s| !s.is_empty() && s != "." && s != "..")
}

/// A catalog entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogEntry {
    pub model: ModelSpec,
    pub licence: Licence,
    /// The origin makes each user accept the model's licence before fetching
    /// the weights. A node fetches them only from network providers, by
    /// content hash, once its operator has accepted the licence
    /// (`--accept-license <id>`), and a provider serves them only to nodes
    /// whose operator has. The licence that gates them is the governing one
    /// (a component's, when a part of the weights is under stricter terms
    /// than the checkpoint), and it must carry an id.
    pub gated: bool,
    pub components: Vec<Component>,
    /// Capability tags the router tiers on (`code`, `reasoning`, ...).
    pub capabilities: Vec<String>,
    /// Published-benchmark prior per use case, in basis points of a perfect
    /// score, used to rank models before any measurement exists.
    pub capability_priors: BTreeMap<String, u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub moe_source: Option<SourceCheckpoint>,
    /// Other entries whose files this entry loads with its own.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<EntryDependency>,
}

/// Why an entry is not usable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{id}: {reason}")]
pub struct EntryError {
    pub id: String,
    pub reason: String,
}

fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-._".contains(&b))
}

fn valid_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 512
        && !path.starts_with('/')
        && !path.contains('\\')
        && path
            .split('/')
            .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

impl CatalogEntry {
    pub fn id(&self) -> &str {
        self.model.id()
    }

    /// The licence a node's operator must have accepted before the node
    /// fetches, holds or serves these weights, when their origin gates them.
    pub fn gating_licence(&self) -> Option<&str> {
        if self.gated {
            self.licence.governing().id
        } else {
            None
        }
    }

    /// The component for `repo`/`path`, if the entry lists one.
    pub fn component(&self, repo: &str, path: &str) -> Option<&Component> {
        self.components
            .iter()
            .find(|c| c.repo == repo && c.path == path)
    }

    /// Every component from `repo`, in path order. For a checkpoint loaded
    /// as a directory these are exactly the files a node fetches.
    pub fn checkpoint(&self, repo: &str) -> Vec<&Component> {
        let mut files: Vec<&Component> =
            self.components.iter().filter(|c| c.repo == repo).collect();
        files.sort_by(|a, b| a.path.cmp(&b.path));
        files
    }

    /// Every repository the entry's components come from, `primary` first,
    /// then the rest in the order the components list them. A checkpoint
    /// assembled from several repositories (weights from one, a text
    /// encoder from another) is fetched one source per directory, each at
    /// its own pinned commit.
    pub fn sources<'a>(&'a self, primary: &'a str) -> Vec<&'a str> {
        let mut out = vec![primary];
        for c in &self.components {
            if !out.contains(&c.repo.as_str()) {
                out.push(&c.repo);
            }
        }
        out
    }

    /// The components of `dep` (the entry named by one of [`Self::requires`])
    /// that this entry loads: those under the dependency's listed parts, in
    /// path order.
    pub fn required_components<'a>(&self, dep: &'a CatalogEntry) -> Vec<&'a Component> {
        let Some(d) = self.requires.iter().find(|d| d.entry == dep.id()) else {
            return Vec::new();
        };
        let mut files: Vec<&Component> = dep
            .components
            .iter()
            .filter(|c| {
                d.parts.iter().any(|p| {
                    c.path == *p
                        || c.path
                            .strip_prefix(p.as_str())
                            .is_some_and(|r| r.starts_with('/'))
                })
            })
            .collect();
        files.sort_by(|a, b| (&a.repo, &a.path).cmp(&(&b.repo, &b.path)));
        files
    }

    /// Every file of the checkpoint directory the entry's pipeline loads:
    /// its own components at their view paths, then the parts of each entry
    /// it requires (`deps`, the entries [`Self::requires`] names) at their
    /// paths.
    ///
    /// # Errors
    /// A required entry missing from `deps`, or two files at one path.
    pub fn checkpoint_view<'a>(
        &'a self,
        deps: &'a [CatalogEntry],
    ) -> Result<Vec<ViewFile<'a>>, String> {
        let mut out: Vec<ViewFile<'a>> = self
            .components
            .iter()
            .map(|c| ViewFile {
                at: c.view_path(),
                entry: self.id(),
                component: c,
            })
            .collect();
        for d in &self.requires {
            let dep = deps
                .iter()
                .find(|e| e.id() == d.entry)
                .ok_or_else(|| format!("{} requires {}, which is not given", self.id(), d.entry))?;
            out.extend(self.required_components(dep).into_iter().map(|c| ViewFile {
                at: &c.path,
                entry: dep.id(),
                component: c,
            }));
        }
        let mut seen = std::collections::HashSet::new();
        if let Some(dup) = out.iter().find(|f| !seen.insert(f.at)) {
            return Err(format!("{}: two files sit at {}", self.id(), dup.at));
        }
        Ok(out)
    }

    /// Every file a node downloads to serve the entry, as `(repo, path)`.
    /// Each must be one of the entry's components.
    pub fn downloads(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        match &self.model {
            ModelSpec::Gguf(e) => {
                out.extend(
                    e.download_files()
                        .into_iter()
                        .map(|p| (e.hf_repo.clone(), p)),
                );
                if let Some(mm) = &e.mmproj {
                    out.push((e.hf_repo.clone(), mm.filename.clone()));
                }
            }
            ModelSpec::Rerank(e) | ModelSpec::Decision(e) => {
                out.push((e.hf_repo.clone(), e.hf_filename.clone()));
                if let Some(mm) = &e.mmproj {
                    out.push((e.hf_repo.clone(), mm.filename.clone()));
                }
            }
            ModelSpec::Embed(e) => {
                out.push((e.hf_repo.clone(), e.hf_filename.clone()));
                if let Some(mm) = &e.mmproj {
                    out.push((e.hf_repo.clone(), mm.filename.clone()));
                }
            }
            ModelSpec::Tts(e) => {
                out.push((e.hf_repo.clone(), e.hf_filename.clone()));
                out.push((e.hf_repo.clone(), e.mmproj_filename.clone()));
            }
            ModelSpec::Omni(e) => {
                out.push((e.hf_repo.clone(), e.hf_filename.clone()));
                out.push((e.hf_repo.clone(), e.mmproj_filename.clone()));
                out.push((e.hf_repo.clone(), e.talker_filename.clone()));
                out.push((e.hf_repo.clone(), e.talker_mmproj_filename.clone()));
            }
            ModelSpec::OnnxForecast(e) => out.push((e.hf_repo.clone(), e.hf_filename.clone())),
            ModelSpec::OnnxTextEmbedding(e) => {
                for f in std::iter::once(&e.hf_filename)
                    .chain(&e.external_data_filenames)
                    .chain(std::iter::once(&e.tokenizer_filename))
                {
                    if !f.is_empty() {
                        out.push((e.hf_repo.clone(), f.clone()));
                    }
                }
            }
            _ => {}
        }
        out
    }

    /// Check the entry is well formed: a valid id, a named licence, hashes of
    /// the right shape, one component per file, and a component for every
    /// file the entry downloads.
    pub fn validate(&self) -> Result<(), EntryError> {
        let id = self.id().to_string();
        let fail = |reason: String| EntryError {
            id: id.clone(),
            reason,
        };
        if !valid_id(&id) {
            return Err(fail(
                "the id must be 1-128 characters of a-z 0-9 - . _".into(),
            ));
        }
        for part in self.licence.parts() {
            if part.name.trim().is_empty() {
                return Err(fail("the licence is not named".into()));
            }
            if part.covers.is_some_and(|c| c.trim().is_empty()) {
                return Err(fail(format!(
                    "{}: the part it covers is not named",
                    part.name
                )));
            }
            if part.tier == LicenseTier::CommercialCustom && part.id.is_none() {
                return Err(fail(format!(
                    "{}: a custom licence needs an id operators can accept",
                    part.name
                )));
            }
            if part.conditions.is_some_and(|c| c.trim().is_empty()) {
                return Err(fail(format!(
                    "{}: the licence conditions are empty",
                    part.name
                )));
            }
        }
        if let ModelSpec::MediaGen(m) = &self.model {
            let pinned = m.engine_rev.as_deref().is_some_and(|r| {
                r.len() == 40
                    && r.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            });
            match m.status {
                crate::MediaGenStatus::Native if !pinned => {
                    return Err(fail(
                        "a native media entry needs the 40-hex engine revision it runs on".into(),
                    ));
                }
                crate::MediaGenStatus::Planned if m.engine_rev.is_some() => {
                    return Err(fail("a planned media entry has no engine revision".into()));
                }
                _ => {}
            }
        }
        if self.gated && self.licence.governing().id.is_none() {
            return Err(fail(
                "a gated entry names no licence id for operators to accept".into(),
            ));
        }
        if let Some(bad) = self.capability_priors.values().find(|v| **v > 10_000) {
            return Err(fail(format!("capability prior {bad} is above 10000")));
        }
        let mut seen = std::collections::BTreeSet::new();
        for c in &self.components {
            if c.repo.is_empty() || c.repo.len() > 256 || !valid_path(&c.path) {
                return Err(fail(format!(
                    "component {}/{} is not a repository path",
                    c.repo, c.path
                )));
            }
            if !is_hex(&c.sha256, 64) {
                return Err(fail(format!(
                    "component {}/{} has no lowercase hex SHA-256",
                    c.repo, c.path
                )));
            }
            match &c.source {
                Source::Hub { revision } => {
                    if !is_hex(revision, 40) {
                        return Err(fail(format!(
                            "component {}/{} is not fixed to a commit",
                            c.repo, c.path
                        )));
                    }
                }
                Source::Network {
                    blake3,
                    built_from,
                    recipe,
                } => {
                    if !is_hex(blake3, 64) {
                        return Err(fail(format!(
                            "component {}/{} has no lowercase hex BLAKE3 content address",
                            c.repo, c.path
                        )));
                    }
                    if built_from.repo.is_empty() || !is_hex(&built_from.revision, 40) {
                        return Err(fail(format!(
                            "component {}/{} does not name the commit it is built from",
                            c.repo, c.path
                        )));
                    }
                    if !valid_path(recipe) {
                        return Err(fail(format!(
                            "component {}/{} does not name the recipe that builds it",
                            c.repo, c.path
                        )));
                    }
                }
            }
            if c.size == 0 {
                return Err(fail(format!("component {}/{} has no size", c.repo, c.path)));
            }
            if c.at.as_deref().is_some_and(|at| !plain_path(at)) {
                return Err(fail(format!(
                    "component {}/{} is placed outside the checkpoint",
                    c.repo, c.path
                )));
            }
            if !seen.insert((c.repo.as_str(), c.path.as_str())) {
                return Err(fail(format!(
                    "component {}/{} is listed twice",
                    c.repo, c.path
                )));
            }
        }
        for (repo, path) in self.downloads() {
            if self.component(&repo, &path).is_none() {
                return Err(fail(format!("{repo}/{path} is downloaded but has no hash")));
            }
        }
        for d in &self.requires {
            if d.entry == id || !valid_id(&d.entry) {
                return Err(fail(format!(
                    "it requires {:?}, which is not another entry id",
                    d.entry
                )));
            }
            if d.parts.is_empty() || d.parts.iter().any(|p| !plain_path(p)) {
                return Err(fail(format!(
                    "its dependency on {} names no loadable parts",
                    d.entry
                )));
            }
        }
        if let Some(src) = &self.moe_source
            && (src.repo.is_empty() || !is_hex(&src.revision, 40))
        {
            return Err(fail(
                "the MoE source checkpoint is not fixed to a commit".into(),
            ));
        }
        Ok(())
    }

    /// The GGUF description, when the engine family is GGUF.
    pub fn gguf(&self) -> Option<&HfModelEntry> {
        match &self.model {
            ModelSpec::Gguf(e) => Some(e),
            _ => None,
        }
    }

    /// The registry row for a GGUF entry served by `provider`. `None` for any
    /// other engine family.
    pub fn model_info(&self, provider: tenzro_types::Address) -> Option<tenzro_types::ModelInfo> {
        self.gguf().map(|e| e.to_model_info(self, provider))
    }
}

impl HfModelEntry {
    /// The registry row for this GGUF model served by `provider`, with the
    /// licence and capabilities its catalog `entry` declares.
    pub fn to_model_info(
        &self,
        entry: &CatalogEntry,
        provider: tenzro_types::Address,
    ) -> tenzro_types::ModelInfo {
        let e = self;
        let mut info = tenzro_types::ModelInfo::new(
            e.id.clone(),
            e.name.clone(),
            e.quantization.clone(),
            tenzro_types::model::ModelModality::Text,
            provider,
        );
        info.architecture = e.architecture.to_string();
        info.description = e.description.clone();
        info.size_bytes = e.size_bytes;
        info.parameters.context_window = e.context_length;
        info.parameters.parameter_count = crate::parse_parameter_count(&e.parameters);
        info.parameters.capabilities = entry.capabilities.clone();
        if let Some(shape) = e.moe {
            info = info.with_moe(shape.to_metadata());
        }
        let governing = entry.licence.governing();
        info.with_license(
            governing.tier,
            entry.licence.name.clone(),
            governing.id.map(str::to_string),
        )
    }
}
