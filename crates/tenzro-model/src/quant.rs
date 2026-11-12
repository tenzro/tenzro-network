//! Precision tiers, and picking the right file out of a repo.
//!
//! # Why this is not string substitution
//!
//! Each catalog entry pins one `hf_filename`, so a model serves only at the
//! quantization the catalog happens to name. Letting a caller ask for a
//! different one looks like a substitution — swap `Q4_K_M` for `Q8_0` in the
//! filename — and that is wrong often enough to be dangerous:
//!
//! ```text
//! Qwen3-0.6B-Q4_K_M.gguf                                    simple
//! gemma-4-31B-it-qat-UD-Q4_K_XL.gguf                        infix marker
//! UD-Q4_K_XL/NVIDIA-Nemotron-3-Ultra-...-00001-of-00009.gguf  dir + shards
//! UD-IQ1_S/Kimi-K3-UD-IQ1_S-00001-of-00014.gguf               14 shards
//! DeepSeek-V4-Pro-IQ2XXS-w2Q2K-AProjQ8-SExpQ8-OutQ8-...gguf    bespoke
//! ```
//!
//! Shard counts differ per tier, so the same model is 9 files at one
//! precision and 14 at another. Substituting the tier token in a shard name
//! produces a path that does not exist, and the failure surfaces as a 404
//! mid-download rather than as "that tier is not published".
//!
//! So [`select_file`] matches against a repo's **actual** file listing.
//!
//! # The collision that matters
//!
//! `Q4_K_M` is a substring of nothing, but `UD-Q4_K_XL` contains `Q4_K_X`,
//! and naive `contains()` matching makes `Q4_K_M` match files it should not
//! and vice versa. Tier matching here is token-aware: a tier matches only
//! when its canonical name appears delimited by a path separator, a hyphen,
//! a dot, or a string boundary. [`tests`] pins that behaviour, because
//! silently serving a 4-bit model to a caller who asked for 8-bit is the kind
//! of bug nobody notices until quality regressions get blamed on the model.

use std::fmt;

use serde::{Deserialize, Serialize};

/// A precision tier a model can be served at.
///
/// Ordered from most to least precise (by bits per weight, ties broken by the
/// wider format first). Covers every GGUF tensor type the pinned engine loads
/// and every Unsloth Dynamic 2.0 (`UD-`) recipe name a registry repository
/// publishes. The nominal bit widths are per weight and approximate: a "4-bit"
/// GGUF stores scales and some tensors at higher precision, and the dynamic
/// quants deliberately upcast important layers. [`QuantTier::bits_per_weight`]
/// is therefore a sizing estimate, not a description of the file format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum QuantTier {
    /// Full 32-bit float. Rare for GGUF; the reference for ONNX.
    F32,
    /// 16-bit brain float. The usual "unquantized" GGUF.
    Bf16,
    /// 16-bit IEEE float.
    F16,
    /// Unsloth Dynamic 8-bit, extra large (important tensors kept wider).
    UdQ8KXl,
    /// 8-bit. Effectively lossless against the source weights.
    Q8_0,
    /// Unsloth Dynamic 6-bit K-quant, extra large.
    UdQ6KXl,
    /// Unsloth Dynamic 6-bit K-quant.
    UdQ6K,
    /// 6-bit K-quant.
    Q6K,
    /// Unsloth Dynamic 5-bit K-quant, extra large.
    UdQ5KXl,
    /// Unsloth Dynamic 5-bit K-quant, medium.
    UdQ5KM,
    /// Unsloth Dynamic 5-bit K-quant, small.
    UdQ5KS,
    /// 5-bit K-quant, medium.
    Q5KM,
    /// 5-bit K-quant, small.
    Q5KS,
    /// MXFP4 mixture-of-experts layout (4-bit micro-scaled floats on the
    /// routed experts, wider elsewhere).
    Mxfp4Moe,
    /// Unsloth Dynamic 2.0 4-bit, extra large. **The default.** Unsloth
    /// measure it on the Pareto frontier at ~99.9% KL divergence, beating
    /// other 4-bit quants while being smaller.
    UdQ4KXl,
    /// Unsloth Dynamic 4-bit K-quant, medium.
    UdQ4KM,
    /// Standard 4-bit K-quant, medium. What most non-Unsloth repos publish.
    Q4KM,
    /// 4-bit K-quant, small.
    Q4KS,
    /// Unsloth Dynamic 4-bit K-quant, small.
    UdQ4KS,
    /// NVFP4 (4-bit floats with E4M3 block scales).
    Nvfp4,
    /// Legacy 4-bit.
    Q4_0,
    /// Non-linear 4-bit i-quant.
    Iq4Nl,
    /// Unsloth Dynamic non-linear 4-bit i-quant.
    UdIq4Nl,
    /// Small 4-bit i-quant.
    Iq4Xs,
    /// Unsloth Dynamic small 4-bit i-quant.
    UdIq4Xs,
    /// Unsloth Dynamic 3-bit K-quant, extra large.
    UdQ3KXl,
    /// Unsloth Dynamic 3-bit K-quant, medium.
    UdQ3KM,
    /// 3-bit K-quant, large.
    Q3KL,
    /// 3-bit K-quant, medium.
    Q3KM,
    /// Unsloth Dynamic 3-bit i-quant, S.
    UdIq3S,
    /// 3-bit K-quant, small.
    Q3KS,
    /// 3-bit i-quant, S.
    Iq3S,
    /// Unsloth Dynamic 3-bit i-quant, extra extra small.
    UdIq3XXS,
    /// 3-bit i-quant.
    Iq3XXS,
    /// Unsloth Dynamic 2-bit K-quant, extra large.
    UdQ2KXl,
    /// 2-bit K-quant.
    Q2K,
    /// Unsloth Dynamic 2-bit i-quant, medium.
    UdIq2M,
    /// 2-bit i-quant, medium.
    Iq2M,
    /// 2-bit i-quant, small.
    Iq2S,
    /// Unsloth Dynamic 2-bit i-quant, extra extra small.
    UdIq2XXS,
    /// 2-bit i-quant, extra small.
    Iq2XS,
    /// 2-bit i-quant. Unsloth measure their IQ2_XXS beating another
    /// quantizer's IQ3_S on real evals despite being 11 GB smaller.
    Iq2XXS,
    /// Ternary 2-bit.
    Tq2_0,
    /// Unsloth Dynamic 1-bit, medium. **Last resort.**
    UdIq1M,
    /// Unsloth Dynamic 1-bit. **Last resort**, for the largest models that
    /// do not otherwise fit at all. Quality degradation is real; prefer any
    /// 2- or 3-bit tier that fits.
    UdIq1S,
    /// Ternary 1.6-bit. **Last resort.**
    Tq1_0,
    /// Unsloth Dynamic 1-bit block format. **Last resort.**
    UdQ1_0,
}

/// One row per tier: the variant, the token as it appears in a GGUF filename
/// and the sizing estimate in bits per weight. Single source for
/// [`QuantTier::ALL`], [`QuantTier::canonical`] and
/// [`QuantTier::bits_per_weight`], so the three cannot drift apart.
///
/// Bits per weight lean above the nominal width because scales, embedding and
/// output tensors ride at higher precision; the figures for the dynamic and
/// low-bit tiers are taken from published file sizes of the largest
/// mixture-of-experts GGUF sets in the registry (Nemotron 3 Ultra, Mistral
/// Large 4), where the routed experts dominate the footprint. Under-estimating
/// would let the memory budget admit a model that does not fit.
const TIER_TABLE: &[(QuantTier, &str, f32)] = &[
    (QuantTier::F32, "F32", 32.0),
    (QuantTier::Bf16, "BF16", 16.0),
    (QuantTier::F16, "F16", 16.0),
    (QuantTier::UdQ8KXl, "UD-Q8_K_XL", 8.7),
    (QuantTier::Q8_0, "Q8_0", 8.5),
    (QuantTier::UdQ6KXl, "UD-Q6_K_XL", 7.0),
    (QuantTier::UdQ6K, "UD-Q6_K", 6.7),
    (QuantTier::Q6K, "Q6_K", 6.6),
    (QuantTier::UdQ5KXl, "UD-Q5_K_XL", 6.2),
    (QuantTier::UdQ5KM, "UD-Q5_K_M", 6.2),
    (QuantTier::UdQ5KS, "UD-Q5_K_S", 5.8),
    (QuantTier::Q5KM, "Q5_K_M", 5.7),
    (QuantTier::Q5KS, "Q5_K_S", 5.5),
    (QuantTier::Mxfp4Moe, "MXFP4_MOE", 5.1),
    (QuantTier::UdQ4KXl, "UD-Q4_K_XL", 4.9),
    (QuantTier::UdQ4KM, "UD-Q4_K_M", 4.85),
    (QuantTier::Q4KM, "Q4_K_M", 4.8),
    (QuantTier::Q4KS, "Q4_K_S", 4.6),
    (QuantTier::UdQ4KS, "UD-Q4_K_S", 4.6),
    (QuantTier::Nvfp4, "NVFP4", 4.5),
    (QuantTier::Q4_0, "Q4_0", 4.5),
    (QuantTier::Iq4Nl, "IQ4_NL", 4.5),
    (QuantTier::UdIq4Nl, "UD-IQ4_NL", 4.4),
    (QuantTier::Iq4Xs, "IQ4_XS", 4.3),
    (QuantTier::UdIq4Xs, "UD-IQ4_XS", 4.3),
    (QuantTier::UdQ3KXl, "UD-Q3_K_XL", 3.9),
    (QuantTier::UdQ3KM, "UD-Q3_K_M", 3.9),
    (QuantTier::Q3KL, "Q3_K_L", 3.9),
    (QuantTier::Q3KM, "Q3_K_M", 3.8),
    (QuantTier::UdIq3S, "UD-IQ3_S", 3.7),
    (QuantTier::Q3KS, "Q3_K_S", 3.5),
    (QuantTier::Iq3S, "IQ3_S", 3.5),
    (QuantTier::UdIq3XXS, "UD-IQ3_XXS", 3.3),
    (QuantTier::Iq3XXS, "IQ3_XXS", 3.1),
    (QuantTier::UdQ2KXl, "UD-Q2_K_XL", 2.95),
    (QuantTier::Q2K, "Q2_K", 2.9),
    (QuantTier::UdIq2M, "UD-IQ2_M", 2.8),
    (QuantTier::Iq2M, "IQ2_M", 2.8),
    (QuantTier::Iq2S, "IQ2_S", 2.6),
    (QuantTier::UdIq2XXS, "UD-IQ2_XXS", 2.5),
    (QuantTier::Iq2XS, "IQ2_XS", 2.5),
    (QuantTier::Iq2XXS, "IQ2_XXS", 2.4),
    (QuantTier::Tq2_0, "TQ2_0", 2.2),
    (QuantTier::UdIq1M, "UD-IQ1_M", 2.0),
    (QuantTier::UdIq1S, "UD-IQ1_S", 1.8),
    (QuantTier::Tq1_0, "TQ1_0", 1.8),
    (QuantTier::UdQ1_0, "UD-Q1_0", 1.5),
];

impl QuantTier {
    /// Every tier, most precise first.
    pub const ALL: &'static [Self] = &[
        Self::F32,
        Self::Bf16,
        Self::F16,
        Self::UdQ8KXl,
        Self::Q8_0,
        Self::UdQ6KXl,
        Self::UdQ6K,
        Self::Q6K,
        Self::UdQ5KXl,
        Self::UdQ5KM,
        Self::UdQ5KS,
        Self::Q5KM,
        Self::Q5KS,
        Self::Mxfp4Moe,
        Self::UdQ4KXl,
        Self::UdQ4KM,
        Self::Q4KM,
        Self::Q4KS,
        Self::UdQ4KS,
        Self::Nvfp4,
        Self::Q4_0,
        Self::Iq4Nl,
        Self::UdIq4Nl,
        Self::Iq4Xs,
        Self::UdIq4Xs,
        Self::UdQ3KXl,
        Self::UdQ3KM,
        Self::Q3KL,
        Self::Q3KM,
        Self::UdIq3S,
        Self::Q3KS,
        Self::Iq3S,
        Self::UdIq3XXS,
        Self::Iq3XXS,
        Self::UdQ2KXl,
        Self::Q2K,
        Self::UdIq2M,
        Self::Iq2M,
        Self::Iq2S,
        Self::UdIq2XXS,
        Self::Iq2XS,
        Self::Iq2XXS,
        Self::Tq2_0,
        Self::UdIq1M,
        Self::UdIq1S,
        Self::Tq1_0,
        Self::UdQ1_0,
    ];

    fn row(self) -> &'static (QuantTier, &'static str, f32) {
        TIER_TABLE
            .iter()
            .find(|(t, _, _)| *t == self)
            .expect("every tier has a row in TIER_TABLE")
    }

    /// The token as it appears in a GGUF filename.
    pub fn canonical(self) -> &'static str {
        self.row().1
    }

    /// Approximate bits per weight, for sizing a model at a tier it has not
    /// been measured at. See [`TIER_TABLE`] for how the figures are chosen.
    pub fn bits_per_weight(self) -> f32 {
        self.row().2
    }

    /// Parse an operator- or caller-supplied tier name.
    ///
    /// Deliberately lenient about case, separators, and a trailing
    /// parenthesised qualifier such as `(QAT)`, because these strings are
    /// typed by hand into config files and RPC params and copied from
    /// registry metadata. `q4_k_m`, `Q4-K-M`, and `Q4KM` all mean the same
    /// thing, and rejecting two of the three helps nobody. The `UD-` prefix
    /// is significant: `UD-Q2_K_XL` and `Q2_K` are different files.
    pub fn parse(s: &str) -> Option<Self> {
        let head = s.split('(').next().unwrap_or(s);
        let norm = normalize(head);
        Self::ALL
            .iter()
            .copied()
            .find(|t| normalize(t.canonical()) == norm)
    }

    /// Estimate this model's size at `self`, given its size at `known_tier`.
    ///
    /// Scales by the bits-per-weight ratio. Approximate by construction —
    /// use it to decide whether a tier is plausible, then admit against the
    /// real file size once the file is known.
    pub fn estimate_size_from(self, known_size_bytes: u64, known_tier: Self) -> u64 {
        let ratio = self.bits_per_weight() / known_tier.bits_per_weight();
        (known_size_bytes as f64 * f64::from(ratio)) as u64
    }

    /// Whether this tier is a desperate measure rather than a choice.
    ///
    /// 1-bit exists so a very large model runs at all on hardware that could
    /// not otherwise hold it. Callers should surface a warning rather than
    /// treat it as an ordinary option.
    pub fn is_last_resort(self) -> bool {
        matches!(
            self,
            Self::UdIq1S | Self::UdIq1M | Self::Tq1_0 | Self::UdQ1_0
        )
    }
}

impl Default for QuantTier {
    /// [`QuantTier::UdQ4KXl`] — Unsloth's Pareto-frontier recommendation.
    fn default() -> Self {
        Self::UdQ4KXl
    }
}

impl fmt::Display for QuantTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.canonical())
    }
}

fn normalize(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

fn is_boundary(c: char) -> bool {
    matches!(c, '/' | '-' | '_' | '.')
}

/// Spans `[start, end)` where `tier`'s token appears in `hay` (already
/// upper-cased) bounded by a path separator, hyphen, underscore, dot or the
/// string ends, and not followed by an underscore-joined size suffix
/// (`Q2_K` inside `Q2_K_XL`).
fn tier_spans(hay: &str, tier: QuantTier) -> Vec<(usize, usize)> {
    const SUFFIXES: &[&str] = &["XXS", "XS", "XL", "NL", "S", "M", "L"];
    let needle = tier.canonical().to_ascii_uppercase();
    let mut spans = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = hay[from..].find(&needle) {
        let start = from + rel;
        let end = start + needle.len();
        let before_ok = start == 0 || hay[..start].chars().next_back().is_some_and(is_boundary);
        let after = &hay[end..];
        let after_ok = after.is_empty()
            || (after.chars().next().is_some_and(is_boundary)
                && !after.strip_prefix('_').is_some_and(|rest| {
                    SUFFIXES.iter().any(|s| {
                        rest.strip_prefix(s)
                            .is_some_and(|r| r.is_empty() || r.starts_with(is_boundary))
                    })
                }));
        if before_ok && after_ok {
            spans.push((start, end));
        }
        from = start + 1;
    }
    spans
}

/// Whether `filename` is a file for `tier`.
///
/// Token-aware rather than a substring test, and longest-token-wins. The tier
/// token must be bounded by a path separator, hyphen, underscore, dot, or the
/// string ends, and an occurrence that lies inside a longer tier's token does
/// not count: `IQ2_XXS` is inside `UD-IQ2_XXS`, `Q4_K_M` inside `UD-Q4_K_M`
/// and `Q2_K` inside `UD-Q2_K_XL`. Without that, a caller asking for the plain
/// tier silently receives the dynamic one, or the reverse, which nobody notices
/// until quality regressions get blamed on the model.
fn matches_tier(filename: &str, tier: QuantTier) -> bool {
    let hay = filename.to_ascii_uppercase();
    let mine = tier_spans(&hay, tier);
    if mine.is_empty() {
        return false;
    }
    let longer: Vec<(usize, usize)> = QuantTier::ALL
        .iter()
        .copied()
        .filter(|t| *t != tier && t.canonical().len() > tier.canonical().len())
        .flat_map(|t| tier_spans(&hay, t))
        .collect();
    mine.iter().any(|&(s, e)| {
        !longer
            .iter()
            .any(|&(ls, le)| ls <= s && e <= le && (ls, le) != (s, e))
    })
}

/// Whether a filename is the first shard of a multi-part set, or unsharded.
///
/// llama.cpp opens a sharded model by its first part and finds the rest, so
/// handing back part 7 of 9 produces a confusing load failure.
fn is_entry_point(filename: &str) -> bool {
    match filename.rfind("-of-") {
        None => true,
        Some(idx) => {
            // `...-00001-of-00009.gguf` — the part before `-of-` ends with
            // the shard index.
            let head = &filename[..idx];
            head.rsplit('-')
                .next()
                .and_then(|n| n.parse::<u32>().ok())
                .is_some_and(|n| n == 1)
        }
    }
}

/// Pick the file to download for `tier` from a repo's listing.
///
/// Returns the single file for an unsharded tier, or the first shard of a
/// sharded one. `None` means the repo does not publish that tier — a
/// distinct outcome from a download failure, and one the caller should
/// report as "not available at that precision" rather than as an error.
pub fn select_file(files: &[String], tier: QuantTier) -> Option<String> {
    let mut candidates: Vec<&String> = files
        .iter()
        .filter(|f| f.ends_with(".gguf"))
        .filter(|f| matches_tier(f, tier))
        .filter(|f| is_entry_point(f))
        .collect();

    // Shortest wins among equals: a repo publishing both
    // `Model-Q4_K_M.gguf` and `Q4_K_M/Model-Q4_K_M-00001-of-00003.gguf`
    // means the plain file is the whole model and the directory is the split
    // copy. Preferring the single file avoids a needless multi-part fetch.
    candidates.sort_by_key(|f| (f.len(), f.as_str().to_string()));
    candidates.first().map(|f| (*f).clone())
}

/// Which tiers a repo actually publishes, most precise first.
///
/// Lets a caller asking for an unavailable tier be told what *is* there,
/// rather than just refused.
pub fn available_tiers(files: &[String]) -> Vec<QuantTier> {
    QuantTier::ALL
        .iter()
        .copied()
        .filter(|t| select_file(files, *t).is_some())
        .collect()
}

/// The closest available tier to `wanted`, preferring more precision.
///
/// Used when a caller names a tier the repo does not publish. Stepping *up*
/// in precision costs memory but never quality; stepping down silently gives
/// the caller a worse model than they asked for, so up is tried first.
pub fn nearest_available(files: &[String], wanted: QuantTier) -> Option<QuantTier> {
    let available = available_tiers(files);
    if available.contains(&wanted) {
        return Some(wanted);
    }
    // `ALL` is ordered most- to least-precise, so the last entry at or above
    // `wanted` is the closest more-precise tier.
    available
        .iter()
        .copied()
        .rfind(|t| *t <= wanted)
        .or_else(|| available.iter().copied().find(|t| *t > wanted))
}

/// Precision an ONNX export is available at.
///
/// # Why this is a suffix and GGUF is not
///
/// GGUF quantization needs a repo listing because shard counts differ per
/// tier and some filenames are bespoke. ONNX is the opposite: `onnx-community`
/// publishes one regular convention — `model.onnx` for fp32 and
/// `model_<dtype>.onnx` for everything else, in the same directory, one file
/// each. Deriving the name is safe here precisely because it is not safe
/// there, and the two cases are kept apart rather than forced into one
/// mechanism that has to be conservative for both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OnnxPrecision {
    /// Full 32-bit float. The reference, and what an export defaults to.
    Fp32,
    /// 16-bit float. Halves the file; some exports are numerically unstable
    /// at this width, which is why entries carry `supports_fp16`.
    Fp16,
    /// 8-bit integer weights.
    Int8,
    /// Unsigned 8-bit.
    Uint8,
    /// 4-bit.
    Q4,
    /// 4-bit weights with fp16 activations.
    Q4F16,
    /// bitsandbytes 4-bit.
    Bnb4,
}

impl OnnxPrecision {
    /// Every precision, most precise first.
    pub const ALL: &'static [Self] = &[
        Self::Fp32,
        Self::Fp16,
        Self::Int8,
        Self::Uint8,
        Self::Q4F16,
        Self::Q4,
        Self::Bnb4,
    ];

    /// Filename suffix, empty for the fp32 default.
    pub fn suffix(self) -> &'static str {
        match self {
            Self::Fp32 => "",
            Self::Fp16 => "_fp16",
            Self::Int8 => "_int8",
            Self::Uint8 => "_uint8",
            Self::Q4 => "_q4",
            Self::Q4F16 => "_q4f16",
            Self::Bnb4 => "_bnb4",
        }
    }

    /// Approximate size relative to fp32.
    ///
    /// Leans high for the same reason the GGUF figures do: an operator warned
    /// unnecessarily is mildly inconvenienced, one who runs out of memory has
    /// an outage.
    pub fn size_ratio(self) -> f32 {
        match self {
            Self::Fp32 => 1.0,
            Self::Fp16 => 0.55,
            Self::Int8 | Self::Uint8 => 0.30,
            Self::Q4F16 => 0.20,
            Self::Q4 | Self::Bnb4 => 0.18,
        }
    }

    /// Parse an operator-supplied name, leniently about case and separators.
    pub fn parse(s: &str) -> Option<Self> {
        let norm = normalize(s);
        Self::ALL.iter().copied().find(|p| {
            let name = if p.suffix().is_empty() {
                "FP32".to_string()
            } else {
                normalize(p.suffix())
            };
            name == norm
        })
    }

    /// Derive the filename for this precision from an fp32 base path.
    ///
    /// `onnx/model.onnx` + [`Self::Fp16`] becomes `onnx/model_fp16.onnx`.
    /// Returns `None` when `base` does not end in `.onnx`, rather than
    /// producing a path that cannot exist.
    pub fn filename_from(self, base: &str) -> Option<String> {
        let stem = base.strip_suffix(".onnx")?;
        // Strip any precision suffix already present, so resolving twice is
        // idempotent rather than producing `model_fp16_int8.onnx`.
        let stem = Self::ALL
            .iter()
            .filter(|p| !p.suffix().is_empty())
            .find_map(|p| stem.strip_suffix(p.suffix()))
            .unwrap_or(stem);
        Some(format!("{stem}{}.onnx", self.suffix()))
    }
}

impl Default for OnnxPrecision {
    /// [`OnnxPrecision::Fp32`] — what an export ships as, and the only width
    /// every entry is known to be numerically stable at.
    fn default() -> Self {
        Self::Fp32
    }
}

impl fmt::Display for OnnxPrecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.suffix().is_empty() {
            "fp32"
        } else {
            self.suffix().trim_start_matches('_')
        })
    }
}

/// Why an ONNX precision cannot be served.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnnxPrecisionError {
    /// The entry declares itself numerically unstable at fp16.
    Fp16Unsupported {
        /// Which model.
        model_id: String,
    },
    /// The base filename is not an `.onnx` path.
    NotAnOnnxPath {
        /// What was given.
        base: String,
    },
}

impl fmt::Display for OnnxPrecisionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fp16Unsupported { model_id } => write!(
                f,
                "{model_id} declares supports_fp16 = false; its export is numerically \
                 unstable at half precision and would return wrong numbers rather than fail"
            ),
            Self::NotAnOnnxPath { base } => {
                write!(f, "'{base}' is not an .onnx path")
            }
        }
    }
}

impl std::error::Error for OnnxPrecisionError {}

/// Resolve an ONNX filename for a requested precision.
///
/// `supports_fp16` comes from the catalog entry. Refusing fp16 on an export
/// that declares itself unstable there is the point: it would not fail, it
/// would return plausible-looking numbers that are wrong, and an embedding
/// that is quietly wrong corrupts a vector index rather than raising an error.
///
/// # Which loaders need this
///
/// Only the ones that fetch from the catalog. Of the seven ONNX runtimes,
/// just text-embedding downloads by model id; vision, segmentation,
/// text-segmentation, detection, audio and forecast all take explicit
/// `encoder_path` / `decoder_path` / `path` arguments, so an operator there
/// already chooses precision by choosing which file to point at. Adding a
/// `precision` parameter to those would be a second way to say the same
/// thing, and a worse one — it could disagree with the path.
pub fn resolve_onnx_precision(
    model_id: &str,
    base_filename: &str,
    precision: OnnxPrecision,
    supports_fp16: bool,
) -> Result<String, OnnxPrecisionError> {
    if matches!(precision, OnnxPrecision::Fp16 | OnnxPrecision::Q4F16) && !supports_fp16 {
        return Err(OnnxPrecisionError::Fp16Unsupported {
            model_id: model_id.to_string(),
        });
    }
    precision
        .filename_from(base_filename)
        .ok_or_else(|| OnnxPrecisionError::NotAnOnnxPath {
            base: base_filename.to_string(),
        })
}

/// List a HuggingFace repo's files.
///
/// [`select_file`] needs the repo's real listing because tier filenames are
/// not derivable — shard counts differ per tier and some names are bespoke.
/// This is the call that gets it.
///
/// Uses the public model API, which returns `siblings` without authentication
/// for the ungated repos the catalog is restricted to. A gated repo returns
/// 401 here rather than failing later mid-download, which is the better place
/// to find out.
pub async fn list_repo_files(hf_repo: &str) -> crate::Result<Vec<String>> {
    Ok(list_repo_entries(hf_repo)
        .await?
        .into_iter()
        .map(|(n, _)| n)
        .collect())
}

/// List a repo's files with their sizes.
///
/// The size matters as much as the name: a caller swapping precision needs to
/// know what the new tier actually weighs, both to admit it against the
/// memory budget and to tell an already-downloaded file of a *different*
/// tier from the one being asked for.
pub async fn list_repo_entries(hf_repo: &str) -> crate::Result<Vec<(String, u64)>> {
    #[derive(serde::Deserialize)]
    struct Sibling {
        rfilename: String,
        #[serde(default)]
        size: Option<u64>,
    }
    #[derive(serde::Deserialize)]
    struct RepoInfo {
        #[serde(default)]
        siblings: Vec<Sibling>,
    }

    // `blobs=true` is required for `siblings` to carry sizes; without it the
    // API returns filenames only, and a caller comparing an on-disk file
    // against the tier it asked for has nothing to compare with.
    let url = format!("https://huggingface.co/api/models/{hf_repo}?blobs=true");
    let client = reqwest::Client::builder()
        // Short relative to a download: this is one small JSON body, and a
        // caller choosing a precision should not wait out a download-length
        // timeout to be told the repo is unreachable.
        .timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()
        .map_err(|e| {
            crate::ModelError::DownloadError(format!("failed to build HTTP client: {e}"))
        })?;

    let request = client.get(&url);
    let response = request.send().await.map_err(|e| {
        crate::ModelError::DownloadError(format!("could not reach the HF API for {hf_repo}: {e}"))
    })?;

    if !response.status().is_success() {
        return Err(crate::ModelError::DownloadError(format!(
            "HF API returned {} for {hf_repo}; the repo may be gated, renamed, or private",
            response.status()
        )));
    }

    let info: RepoInfo = response.json().await.map_err(|e| {
        crate::ModelError::DownloadError(format!("malformed HF API response for {hf_repo}: {e}"))
    })?;

    Ok(info
        .siblings
        .into_iter()
        .map(|s| (s.rfilename, s.size.unwrap_or(0)))
        .collect())
}

/// What a caller gets back when asking to serve a model at a chosen precision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedQuant {
    /// The tier actually resolved. May differ from the request when the repo
    /// does not publish it — see `substituted`.
    pub tier: QuantTier,
    /// Repo-relative path to download.
    pub filename: String,
    /// True when the requested tier was unavailable and a nearer one was
    /// chosen. Callers should surface this: silently serving a different
    /// precision than asked for is how quality regressions get misattributed.
    pub substituted: bool,
    /// Every tier this repo publishes, so a caller told "not available" can
    /// see what is.
    pub available: Vec<QuantTier>,
    /// On-disk size of the resolved file, in bytes.
    ///
    /// For a sharded set this is the first shard only; `0` when the hub did
    /// not report a size. Callers admitting against a memory budget should
    /// treat `0` as "unknown" rather than as "free".
    pub size_bytes: u64,
}

/// Resolve a requested precision against a repo, falling back if needed.
///
/// Returns an error only when the repo publishes no usable GGUF at all.
/// A tier that merely is not published resolves to the nearest available one
/// with `substituted: true`, because refusing outright would make a caller
/// guess which precisions exist.
pub async fn resolve(hf_repo: &str, wanted: QuantTier) -> crate::Result<ResolvedQuant> {
    let entries = list_repo_entries(hf_repo).await?;
    let files: Vec<String> = entries.iter().map(|(n, _)| n.clone()).collect();
    let available = available_tiers(&files);

    let tier = nearest_available(&files, wanted).ok_or_else(|| {
        crate::ModelError::DownloadError(format!(
            "{hf_repo} publishes no GGUF this node can select a precision from"
        ))
    })?;

    let filename = select_file(&files, tier).ok_or_else(|| {
        crate::ModelError::DownloadError(format!(
            "{hf_repo} lists {tier} but no downloadable entry-point file for it"
        ))
    })?;

    let size_bytes = entries
        .iter()
        .find(|(n, _)| *n == filename)
        .map(|(_, sz)| *sz)
        .unwrap_or(0);

    Ok(ResolvedQuant {
        tier,
        filename,
        substituted: tier != wanted,
        available,
        size_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files() -> Vec<String> {
        [
            "Qwen3-0.6B-Q4_K_M.gguf",
            "Qwen3-0.6B-Q8_0.gguf",
            "UD-Q4_K_XL/Qwen3-0.6B-UD-Q4_K_XL-00001-of-00003.gguf",
            "UD-Q4_K_XL/Qwen3-0.6B-UD-Q4_K_XL-00002-of-00003.gguf",
            "UD-Q4_K_XL/Qwen3-0.6B-UD-Q4_K_XL-00003-of-00003.gguf",
            "README.md",
            "config.json",
        ]
        .into_iter()
        .map(String::from)
        .collect()
    }

    // ── ONNX precision ────────────────────────────────────────────────

    #[test]
    fn onnx_filenames_follow_the_onnx_community_suffix_convention() {
        // Verified against onnx-community/Qwen3-Embedding-0.6B-ONNX, which
        // publishes exactly this set.
        let base = "onnx/model.onnx";
        assert_eq!(
            OnnxPrecision::Fp32.filename_from(base).unwrap(),
            "onnx/model.onnx"
        );
        assert_eq!(
            OnnxPrecision::Fp16.filename_from(base).unwrap(),
            "onnx/model_fp16.onnx"
        );
        assert_eq!(
            OnnxPrecision::Int8.filename_from(base).unwrap(),
            "onnx/model_int8.onnx"
        );
        assert_eq!(
            OnnxPrecision::Q4F16.filename_from(base).unwrap(),
            "onnx/model_q4f16.onnx"
        );
        assert_eq!(
            OnnxPrecision::Bnb4.filename_from(base).unwrap(),
            "onnx/model_bnb4.onnx"
        );
    }

    #[test]
    fn resolving_a_precision_twice_does_not_stack_suffixes() {
        // A caller re-resolving an already-resolved path must not produce
        // `model_fp16_int8.onnx`, which exists nowhere.
        let once = OnnxPrecision::Fp16
            .filename_from("onnx/model.onnx")
            .unwrap();
        let twice = OnnxPrecision::Int8.filename_from(&once).unwrap();
        assert_eq!(twice, "onnx/model_int8.onnx");
    }

    #[test]
    fn a_non_onnx_path_is_refused_rather_than_mangled() {
        assert!(
            OnnxPrecision::Fp16
                .filename_from("model.safetensors")
                .is_none()
        );
        let err = resolve_onnx_precision("m", "model.bin", OnnxPrecision::Int8, true)
            .expect_err("not an onnx path");
        assert!(matches!(err, OnnxPrecisionError::NotAnOnnxPath { .. }));
    }

    #[test]
    fn fp16_is_refused_on_an_export_that_declares_itself_unstable() {
        // EmbeddingGemma is the real case. This would not fail at runtime —
        // it would return plausible-looking numbers that are wrong, and an
        // embedding that is quietly wrong corrupts a vector index rather than
        // raising anything.
        let err = resolve_onnx_precision(
            "embeddinggemma-300m",
            "onnx/model.onnx",
            OnnxPrecision::Fp16,
            false,
        )
        .expect_err("must refuse");
        assert!(matches!(err, OnnxPrecisionError::Fp16Unsupported { .. }));
        assert!(err.to_string().contains("wrong numbers"), "{err}");

        // The mixed 4-bit/fp16 width carries the same hazard.
        assert!(
            resolve_onnx_precision("e", "onnx/model.onnx", OnnxPrecision::Q4F16, false).is_err()
        );

        // Integer widths are unaffected by fp16 instability.
        assert!(resolve_onnx_precision("e", "onnx/model.onnx", OnnxPrecision::Int8, false).is_ok());
        assert!(resolve_onnx_precision("e", "onnx/model.onnx", OnnxPrecision::Fp32, false).is_ok());
    }

    #[test]
    fn onnx_precision_names_parse_however_they_are_typed() {
        for s in ["fp16", "FP16", "_fp16"] {
            assert_eq!(OnnxPrecision::parse(s), Some(OnnxPrecision::Fp16), "{s}");
        }
        assert_eq!(OnnxPrecision::parse("fp32"), Some(OnnxPrecision::Fp32));
        assert_eq!(OnnxPrecision::parse("q4f16"), Some(OnnxPrecision::Q4F16));
        assert_eq!(OnnxPrecision::parse("nonsense"), None);
    }

    #[test]
    fn the_onnx_default_is_the_width_every_export_is_stable_at() {
        // fp32 is what an export ships as, and the only width no entry
        // declares itself unsafe at.
        assert_eq!(OnnxPrecision::default(), OnnxPrecision::Fp32);
        assert_eq!(OnnxPrecision::Fp32.size_ratio(), 1.0);
    }

    #[test]
    fn onnx_size_ratios_run_from_most_to_least_precise() {
        let ratios: Vec<f32> = OnnxPrecision::ALL.iter().map(|p| p.size_ratio()).collect();
        for w in ratios.windows(2) {
            assert!(w[0] >= w[1], "ALL must be ordered by precision: {ratios:?}");
        }
    }

    #[test]
    fn precision_scaling_shrinks_the_declared_footprint() {
        // The memory budget admits against size_bytes, so a caller loading
        // int8 must not be charged for fp32 — that would refuse loads that
        // comfortably fit.
        let fp32 = 2_400_000_000u64;
        let int8 = (fp32 as f64 * f64::from(OnnxPrecision::Int8.size_ratio())) as u64;
        let q4 = (fp32 as f64 * f64::from(OnnxPrecision::Q4.size_ratio())) as u64;
        assert!(int8 < fp32 / 2, "int8 should be well under half fp32");
        assert!(q4 < int8, "4-bit should be smaller than 8-bit");
    }

    #[tokio::test]
    #[ignore = "hits the HuggingFace API; run with --run-ignored"]
    async fn the_suffix_convention_matches_a_real_onnx_repo() {
        // The whole scheme rests on onnx-community's naming holding. If they
        // change it, deriving filenames silently starts producing 404s, and
        // this is what catches that.
        let files = list_repo_files("onnx-community/Qwen3-Embedding-0.6B-ONNX")
            .await
            .expect("public repo");
        for p in [
            OnnxPrecision::Fp32,
            OnnxPrecision::Fp16,
            OnnxPrecision::Int8,
            OnnxPrecision::Q4,
        ] {
            let want = p.filename_from("onnx/model.onnx").unwrap();
            assert!(
                files.contains(&want),
                "derived {want} for {p} but the repo has: {:?}",
                files
                    .iter()
                    .filter(|f| f.ends_with(".onnx"))
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn a_four_bit_request_does_not_match_the_unsloth_four_bit_file() {
        // The collision this module exists to prevent. `Q4_K_M` must not
        // match `UD-Q4_K_XL` files, or a caller asking for the standard
        // quant silently receives the Unsloth one and vice versa.
        assert_eq!(
            select_file(&files(), QuantTier::Q4KM).as_deref(),
            Some("Qwen3-0.6B-Q4_K_M.gguf")
        );
        assert_eq!(
            select_file(&files(), QuantTier::UdQ4KXl).as_deref(),
            Some("UD-Q4_K_XL/Qwen3-0.6B-UD-Q4_K_XL-00001-of-00003.gguf")
        );
    }

    #[test]
    fn a_sharded_tier_resolves_to_its_first_part() {
        // llama.cpp opens a split model by part 1 and finds the rest; part 2
        // produces a confusing load failure.
        let picked = select_file(&files(), QuantTier::UdQ4KXl).expect("published");
        assert!(picked.contains("00001-of-00003"), "{picked}");
    }

    #[test]
    fn a_tier_the_repo_does_not_publish_is_none_not_a_guess() {
        // "Not published at that precision" and "download failed" are
        // different things and callers respond to them differently.
        assert_eq!(select_file(&files(), QuantTier::UdIq1S), None);
        assert_eq!(select_file(&files(), QuantTier::Bf16), None);
    }

    #[test]
    fn non_gguf_files_are_never_selected() {
        let listing = vec!["config.json".to_string(), "Model-Q8_0.txt".to_string()];
        assert_eq!(select_file(&listing, QuantTier::Q8_0), None);
    }

    #[test]
    fn an_unsharded_file_beats_a_split_copy_of_the_same_tier() {
        // Some repos publish both. Fetching one file is better than three.
        let listing = vec![
            "Q4_K_M/Model-Q4_K_M-00001-of-00003.gguf".to_string(),
            "Model-Q4_K_M.gguf".to_string(),
        ];
        assert_eq!(
            select_file(&listing, QuantTier::Q4KM).as_deref(),
            Some("Model-Q4_K_M.gguf")
        );
    }

    #[test]
    fn a_qat_infix_filename_still_matches_its_tier() {
        // Real catalog entry: gemma-4-31B-it-qat-UD-Q4_K_XL.gguf
        let listing = vec!["gemma-4-31B-it-qat-UD-Q4_K_XL.gguf".to_string()];
        assert_eq!(
            select_file(&listing, QuantTier::UdQ4KXl).as_deref(),
            Some("gemma-4-31B-it-qat-UD-Q4_K_XL.gguf")
        );
    }

    #[test]
    fn tier_names_parse_however_an_operator_types_them() {
        for s in ["Q4_K_M", "q4_k_m", "Q4-K-M", "q4km", "  Q4_K_M  "] {
            assert_eq!(QuantTier::parse(s.trim()), Some(QuantTier::Q4KM), "{s}");
        }
        for s in ["UD-Q4_K_XL", "ud-q4-k-xl", "udq4kxl"] {
            assert_eq!(QuantTier::parse(s), Some(QuantTier::UdQ4KXl), "{s}");
        }
        assert_eq!(QuantTier::parse("nonsense"), None);
    }

    #[test]
    fn the_default_is_the_pareto_frontier_tier_not_the_smallest() {
        // Defaulting to 1-bit would make every model fit and every model bad.
        assert_eq!(QuantTier::default(), QuantTier::UdQ4KXl);
        assert!(!QuantTier::default().is_last_resort());
        assert!(QuantTier::UdIq1S.is_last_resort());
    }

    #[test]
    fn precision_ordering_runs_from_most_to_least() {
        let bits: Vec<f32> = QuantTier::ALL.iter().map(|t| t.bits_per_weight()).collect();
        for pair in bits.windows(2) {
            assert!(
                pair[0] >= pair[1],
                "ALL must be ordered most- to least-precise: {pair:?}"
            );
        }
        assert!(QuantTier::F32 < QuantTier::UdIq1S, "Ord follows precision");
    }

    #[test]
    fn size_estimates_scale_the_right_way() {
        // A 20 GB 4-bit model is roughly 35 GB at 8-bit and roughly 7 GB at
        // 1-bit. The memory budget admits against these before the real file
        // size is known.
        const GB: u64 = 1_000_000_000;
        let at_8 = QuantTier::Q8_0.estimate_size_from(20 * GB, QuantTier::UdQ4KXl);
        let at_1 = QuantTier::UdIq1S.estimate_size_from(20 * GB, QuantTier::UdQ4KXl);
        assert!(at_8 > 30 * GB && at_8 < 40 * GB, "{at_8}");
        assert!(at_1 > 5 * GB && at_1 < 10 * GB, "{at_1}");
        // Estimating at the known tier is the identity.
        assert_eq!(
            QuantTier::UdQ4KXl.estimate_size_from(20 * GB, QuantTier::UdQ4KXl),
            20 * GB
        );
    }

    #[test]
    fn bits_per_weight_leans_above_the_nominal_width() {
        // Under-estimating would let the memory budget admit a model that
        // does not fit, which is an OOM rather than a refusal.
        assert!(QuantTier::Q4KM.bits_per_weight() > 4.0);
        assert!(QuantTier::Q8_0.bits_per_weight() > 8.0);
        assert!(QuantTier::UdIq1S.bits_per_weight() > 1.0);
    }

    #[test]
    fn available_tiers_reports_what_the_repo_actually_has() {
        let got = available_tiers(&files());
        assert_eq!(
            got,
            vec![QuantTier::Q8_0, QuantTier::UdQ4KXl, QuantTier::Q4KM]
        );
    }

    #[test]
    fn an_unavailable_tier_falls_upward_to_more_precision_not_down() {
        // Stepping up costs memory but never quality. Stepping down hands the
        // caller a worse model than they asked for without telling them.
        let listing = files();
        assert_eq!(
            nearest_available(&listing, QuantTier::UdIq1S),
            Some(QuantTier::Q4KM),
            "1-bit unavailable: take the least-precise tier that exists"
        );
        assert_eq!(
            nearest_available(&listing, QuantTier::Bf16),
            Some(QuantTier::Q8_0),
            "16-bit unavailable: fall to the most precise that exists"
        );
        assert_eq!(
            nearest_available(&listing, QuantTier::Q4KM),
            Some(QuantTier::Q4KM),
            "an available tier is returned unchanged"
        );
    }

    #[test]
    fn nearest_available_on_an_empty_repo_is_none() {
        assert_eq!(nearest_available(&[], QuantTier::Q4KM), None);
    }

    #[tokio::test]
    #[ignore = "hits the HuggingFace API; run with --run-ignored"]
    async fn a_real_repo_lists_the_tiers_it_actually_publishes() {
        // The unit tests above use a synthetic listing, which proves the
        // matching logic but not that the shapes match reality. This checks
        // the assumption the whole module rests on: that HF's `siblings`
        // field names files the way `select_file` expects.
        let files = list_repo_files("unsloth/Qwen3-0.6B-GGUF")
            .await
            .expect("public ungated repo should list");
        assert!(!files.is_empty(), "listing must not be empty");
        assert!(
            files.iter().any(|f| f.ends_with(".gguf")),
            "a GGUF repo must contain GGUFs, got: {files:?}"
        );

        let tiers = available_tiers(&files);
        assert!(
            !tiers.is_empty(),
            "no tier matched real filenames — the matcher has drifted from \
             upstream naming. Files: {files:?}"
        );
    }

    #[tokio::test]
    #[ignore = "hits the HuggingFace API; run with --run-ignored"]
    async fn resolving_reports_the_tiers_real_size_not_the_catalogs() {
        // Found live: asking for Q8_0 when Q4_K_M was already on disk
        // returned "completed" and left the 4-bit file in place, because the
        // already-downloaded check compared against the catalog's size for
        // its own pinned tier. The resolver has to report what the chosen
        // tier actually weighs or that check cannot tell them apart.
        let q4 = resolve("unsloth/Qwen3-0.6B-GGUF", QuantTier::Q4KM)
            .await
            .expect("published");
        let q8 = resolve("unsloth/Qwen3-0.6B-GGUF", QuantTier::Q8_0)
            .await
            .expect("published");

        assert!(
            q4.size_bytes > 0 && q8.size_bytes > 0,
            "sizes must be reported"
        );
        assert!(
            q8.size_bytes > q4.size_bytes,
            "8-bit must weigh more than 4-bit: {} vs {}",
            q8.size_bytes,
            q4.size_bytes
        );
        assert_ne!(q4.filename, q8.filename);
    }

    #[tokio::test]
    #[ignore = "hits the HuggingFace API; run with --run-ignored"]
    async fn resolving_an_unpublished_tier_substitutes_and_says_so() {
        // The caller must be able to tell "you got what you asked for" from
        // "you got the nearest thing", or a precision substitution silently
        // becomes an unexplained quality change.
        let resolved = resolve("unsloth/Qwen3-0.6B-GGUF", QuantTier::default())
            .await
            .expect("repo resolves");
        assert!(resolved.filename.ends_with(".gguf"));
        assert!(!resolved.available.is_empty());
        if resolved.substituted {
            assert_ne!(resolved.tier, QuantTier::default());
        }
    }

    #[tokio::test]
    #[ignore = "hits the HuggingFace API; run with --run-ignored"]
    async fn a_missing_repo_fails_at_resolve_rather_than_mid_download() {
        // Finding out at listing time is much better than a 404 partway
        // through fetching several gigabytes.
        let err = list_repo_files("unsloth/definitely-not-a-real-repo-xyzzy")
            .await
            .expect_err("nonexistent repo must error");
        let msg = err.to_string();
        assert!(
            msg.contains("gated") || msg.contains("404") || msg.contains("renamed"),
            "error should explain what went wrong: {msg}"
        );
    }

    #[test]
    fn a_shard_that_is_not_the_first_is_never_an_entry_point() {
        assert!(is_entry_point("Model-Q4_K_M.gguf"));
        assert!(is_entry_point("Model-Q4_K_M-00001-of-00009.gguf"));
        assert!(!is_entry_point("Model-Q4_K_M-00002-of-00009.gguf"));
        assert!(!is_entry_point("Model-Q4_K_M-00009-of-00009.gguf"));
    }
}

#[cfg(test)]
mod tier_coverage {
    use super::*;

    #[test]
    fn the_table_and_the_ordered_list_name_the_same_tiers() {
        assert_eq!(TIER_TABLE.len(), QuantTier::ALL.len());
        for (i, t) in QuantTier::ALL.iter().enumerate() {
            assert_eq!(TIER_TABLE[i].0, *t, "row {i} is out of order");
            assert_eq!(QuantTier::parse(t.canonical()), Some(*t), "{t}");
        }
        let mut names: Vec<&str> = TIER_TABLE.iter().map(|r| r.1).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), TIER_TABLE.len(), "duplicate canonical token");
    }

    #[test]
    fn every_registry_quant_name_is_a_tier() {
        // The names the registry repositories publish for the Nemotron 3
        // Ultra, Nemotron 3.5 Bolt and Mistral Large 4 sets, plus the
        // generic llama.cpp names.
        for name in [
            "BF16",
            "Q8_0",
            "UD-Q8_K_XL",
            "UD-Q6_K_XL",
            "UD-Q6_K",
            "UD-Q5_K_XL",
            "UD-Q5_K_M",
            "UD-Q5_K_S",
            "MXFP4_MOE",
            "UD-Q4_K_XL",
            "UD-Q4_K_M",
            "UD-Q4_K_S",
            "UD-IQ4_NL",
            "UD-IQ4_XS",
            "UD-Q3_K_XL",
            "UD-Q3_K_M",
            "UD-IQ3_S",
            "UD-IQ3_XXS",
            "UD-Q2_K_XL",
            "UD-IQ2_M",
            "UD-IQ2_XXS",
            "UD-IQ1_M",
            "UD-IQ1_S",
            "UD-Q1_0",
            "IQ2_XXS",
            "Q2_K",
            "Q3_K_M",
            "IQ3_S",
            "IQ4_XS",
            "Q4_0",
            "NVFP4",
            "TQ1_0",
        ] {
            assert!(QuantTier::parse(name).is_some(), "{name} is not a tier");
        }
        // Registry metadata carries a qualifier after the tier.
        assert_eq!(
            QuantTier::parse("UD-Q4_K_XL (QAT)"),
            Some(QuantTier::UdQ4KXl)
        );
        // The prefix is significant.
        assert_ne!(QuantTier::parse("Q2_K"), QuantTier::parse("UD-Q2_K_XL"));
    }

    fn ultra_like_listing() -> Vec<String> {
        let mut v = Vec::new();
        for (dir, n) in [
            ("UD-IQ1_M", 5),
            ("UD-IQ2_XXS", 5),
            ("UD-Q2_K_XL", 6),
            ("UD-Q3_K_XL", 7),
            ("UD-Q4_K_XL", 9),
            ("UD-Q6_K", 11),
            ("UD-Q6_K_XL", 12),
            ("UD-Q8_K_XL", 14),
            ("Q8_0", 14),
            ("MXFP4_MOE", 9),
        ] {
            for i in 1..=n {
                v.push(format!("{dir}/M-{dir}-{i:05}-of-{n:05}.gguf"));
            }
        }
        v.push("M-IQ2_XXS.gguf".into());
        v.push("M-Q2_K.gguf".into());
        v
    }

    #[test]
    fn a_plain_tier_never_selects_the_dynamic_file_of_the_same_name() {
        let files = ultra_like_listing();
        assert_eq!(
            select_file(&files, QuantTier::Iq2XXS).as_deref(),
            Some("M-IQ2_XXS.gguf")
        );
        assert_eq!(
            select_file(&files, QuantTier::UdIq2XXS).as_deref(),
            Some("UD-IQ2_XXS/M-UD-IQ2_XXS-00001-of-00005.gguf")
        );
        assert_eq!(
            select_file(&files, QuantTier::Q2K).as_deref(),
            Some("M-Q2_K.gguf")
        );
        assert_eq!(
            select_file(&files, QuantTier::UdQ2KXl).as_deref(),
            Some("UD-Q2_K_XL/M-UD-Q2_K_XL-00001-of-00006.gguf")
        );
        // Q6_K does not match UD-Q6_K_XL or UD-Q6_K; the repo has no plain one.
        assert_eq!(select_file(&files, QuantTier::Q6K), None);
        assert_eq!(
            select_file(&files, QuantTier::UdQ6K).as_deref(),
            Some("UD-Q6_K/M-UD-Q6_K-00001-of-00011.gguf")
        );
        assert_eq!(
            select_file(&files, QuantTier::UdQ6KXl).as_deref(),
            Some("UD-Q6_K_XL/M-UD-Q6_K_XL-00001-of-00012.gguf")
        );
    }

    #[test]
    fn available_tiers_lists_each_published_tier_exactly_once() {
        let got = available_tiers(&ultra_like_listing());
        assert_eq!(
            got,
            vec![
                QuantTier::UdQ8KXl,
                QuantTier::Q8_0,
                QuantTier::UdQ6KXl,
                QuantTier::UdQ6K,
                QuantTier::Mxfp4Moe,
                QuantTier::UdQ4KXl,
                QuantTier::UdQ3KXl,
                QuantTier::UdQ2KXl,
                QuantTier::Q2K,
                QuantTier::UdIq2XXS,
                QuantTier::Iq2XXS,
                QuantTier::UdIq1M,
            ]
        );
    }

    #[test]
    fn last_resort_tiers_are_the_one_bit_family() {
        for t in QuantTier::ALL {
            let one_bit = t.bits_per_weight() <= 2.0;
            assert_eq!(t.is_last_resort(), one_bit, "{t}");
        }
    }

    #[test]
    fn ultra_sizes_estimated_from_the_four_bit_file_land_near_the_published_ones() {
        // Published Nemotron 3 Ultra sizes, GB: UD-Q4_K_XL 360.2, UD-Q8_K_XL
        // 594.5, UD-IQ1_M 188.0, UD-Q2_K_XL 202.2.
        let base = 360_200_000_000u64;
        let within = |est: u64, real: f64, tol: f64| {
            let e = est as f64 / 1e9;
            (e - real).abs() / real < tol
        };
        assert!(within(
            QuantTier::UdQ8KXl.estimate_size_from(base, QuantTier::UdQ4KXl),
            594.5,
            0.25
        ));
        assert!(within(
            QuantTier::UdQ2KXl.estimate_size_from(base, QuantTier::UdQ4KXl),
            202.2,
            0.25
        ));
        assert!(within(
            QuantTier::UdIq1M.estimate_size_from(base, QuantTier::UdQ4KXl),
            188.0,
            0.25
        ));
    }
}
