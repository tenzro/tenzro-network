//! Units of billable and observed work, as data.
//!
//! A unit is a record in the on-chain unit registry ([`UnitDef`]), not a
//! field in a struct: a model type that bills on something new (action chunks
//! of a robot policy, simulated seconds of a world model, watt-hours a charger
//! delivered) registers the unit and lists it in its catalog entry, and every
//! receipt, usage record, price card and settlement carries it without a code
//! change.
//!
//! A quantity is recorded under a *meter key*: the unit id alone, or the unit
//! id and a tier (`input_tokens@ctx_gt_200k`, `output_tokens@priority`,
//! `video_out_ms@4k`). A tier means exactly what the price card that prices
//! it says; it needs no registration, and a charge can only use a tier the
//! card lists.

use serde::{Deserialize, Serialize};

/// Longest unit id.
pub const MAX_UNIT_ID_LEN: usize = 40;
/// Longest tier.
pub const MAX_TIER_LEN: usize = 24;
/// Separator between a unit id and its tier in a meter key.
pub const TIER_SEPARATOR: char = '@';

/// Ids of the units the network starts with. Anyone may register more.
pub mod unit {
    pub const INPUT_TOKENS: &str = "input_tokens";
    pub const OUTPUT_TOKENS: &str = "output_tokens";
    pub const REASONING_TOKENS: &str = "reasoning_tokens";
    pub const CACHED_READ_TOKENS: &str = "cached_read_tokens";
    pub const CACHED_WRITE_TOKENS: &str = "cached_write_tokens";
    pub const REASONING_LOOPS: &str = "reasoning_loops";
    pub const IMAGE_TOKENS: &str = "image_tokens";
    pub const AUDIO_MS: &str = "audio_ms";
    pub const VIDEO_MS: &str = "video_ms";
    pub const PIXEL_STEPS: &str = "pixel_steps";
    pub const MEGAPIXELS: &str = "megapixels";
    pub const IMAGES: &str = "images";
    pub const FRAMES: &str = "frames";
    pub const VIDEO_OUT_MS: &str = "video_out_ms";
    pub const CHARACTERS: &str = "characters";
    pub const AUDIO_OUT_MS: &str = "audio_out_ms";
    pub const RERANK_PAIRS: &str = "rerank_pairs";
    pub const DECISION_QUESTIONS: &str = "decision_questions";
    pub const FORECAST_POINTS: &str = "forecast_points";
    pub const TRAINED_TOKENS: &str = "trained_tokens";
    pub const SIMULATED_MS: &str = "simulated_ms";
    pub const SESSION_HOLD_MS: &str = "session_hold_ms";
    pub const SESSION_MS: &str = "session_ms";
    pub const ACTION_CHUNKS: &str = "action_chunks";
    pub const CONTROL_STEPS: &str = "control_steps";
    pub const ASSETS: &str = "assets";
    pub const WORLDS: &str = "worlds";
    pub const ACCEL_MS: &str = "accel_ms";
    pub const REQUESTS: &str = "requests";
    pub const TTFT_MS: &str = "ttft_ms";
    pub const DECODE_MS: &str = "decode_ms";
}

/// Who can check a unit's count, which decides how a disputed count is
/// settled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Witness {
    /// The payer counts it from what it sent and received, so it simply does
    /// not pay for a count it disagrees with.
    Payer,
    /// Hidden from the payer but reproducible by re-running the request
    /// under the receipt's decode, so a sampled or challenged re-execution
    /// settles it.
    Reexec,
    /// Only the provider observes it; its meter bond stands behind it.
    Provider,
    /// A reading signed by a device's hardware identity.
    Device,
    /// Measured by validators, as service availability is.
    Validator,
}

/// One registered unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitDef {
    /// Immutable id; see [`valid_unit_id`].
    pub id: String,
    /// What one unit is: `count`, `ms`, `bytes`, `mwh`, ... (at most 16
    /// characters, free text).
    pub scale: String,
    pub witness: Witness,
    /// `false` for a unit that is recorded but never charged, such as time
    /// to first token: routers and reputation read it, a price card cannot
    /// price it.
    pub billable: bool,
    /// Most of this unit one call may report, or 0 for no unit-level bound.
    #[serde(with = "crate::primitives::u128_serde")]
    pub max_per_call: u128,
    /// SHA-256 of the definition of how the unit is counted, hex.
    pub doc_hash: String,
}

/// Longest [`UnitDef::scale`].
pub const MAX_SCALE_LEN: usize = 16;

/// Why a unit definition or meter key is not acceptable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MeterError {
    #[error("'{0}' is not a unit id: 1..={MAX_UNIT_ID_LEN} of [a-z0-9_], starting with a letter")]
    BadUnitId(String),
    #[error(
        "'{0}' is not a meter key: unit id, optionally '@' and a tier of 1..={MAX_TIER_LEN} [a-z0-9_]"
    )]
    BadKey(String),
    #[error("scale must be 1..={MAX_SCALE_LEN} printable ASCII characters")]
    BadScale,
    #[error("doc_hash must be 64 lower-case hex characters")]
    BadDocHash,
    #[error("quantity of '{0}' overflows")]
    Overflow(String),
}

fn word(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// A unit id: 1..=40 of `[a-z0-9_]`, starting with a letter.
pub fn valid_unit_id(id: &str) -> bool {
    word(id, MAX_UNIT_ID_LEN) && id.as_bytes()[0].is_ascii_lowercase()
}

/// Split a meter key into its unit id and tier, checking both.
pub fn parse_key(key: &str) -> Result<(&str, Option<&str>), MeterError> {
    let (unit, tier) = match key.split_once(TIER_SEPARATOR) {
        Some((u, t)) => (u, Some(t)),
        None => (key, None),
    };
    if !valid_unit_id(unit) || tier.is_some_and(|t| !word(t, MAX_TIER_LEN)) {
        return Err(MeterError::BadKey(key.to_string()));
    }
    Ok((unit, tier))
}

/// The meter key for `unit` at `tier`.
pub fn key(unit: &str, tier: Option<&str>) -> String {
    match tier {
        Some(t) => format!("{unit}{TIER_SEPARATOR}{t}"),
        None => unit.to_string(),
    }
}

impl UnitDef {
    /// Check the definition's own fields.
    pub fn validate(&self) -> Result<(), MeterError> {
        if !valid_unit_id(&self.id) {
            return Err(MeterError::BadUnitId(self.id.clone()));
        }
        if self.scale.is_empty()
            || self.scale.len() > MAX_SCALE_LEN
            || !self.scale.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(MeterError::BadScale);
        }
        if self.doc_hash.len() != 64
            || !self
                .doc_hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(MeterError::BadDocHash);
        }
        Ok(())
    }
}

/// The units the network is created with.
pub fn genesis_units() -> Vec<UnitDef> {
    use Witness::*;
    use unit::*;
    let def = |id: &str, scale: &str, witness: Witness, billable: bool, what: &str| UnitDef {
        id: id.to_string(),
        scale: scale.to_string(),
        witness,
        billable,
        max_per_call: 0,
        doc_hash: {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(what.as_bytes()))
        },
    };
    vec![
        def(
            INPUT_TOKENS,
            "count",
            Payer,
            true,
            "Prompt tokens prefilled fresh, under the tokenizer the catalog entry pins, excluding tokens served from cache.",
        ),
        def(
            OUTPUT_TOKENS,
            "count",
            Payer,
            true,
            "Tokens emitted to the caller.",
        ),
        def(
            REASONING_TOKENS,
            "count",
            Reexec,
            true,
            "Tokens generated but not emitted, such as hidden reasoning, reproducible under the receipt's decode.",
        ),
        def(
            CACHED_READ_TOKENS,
            "count",
            Reexec,
            true,
            "Prompt tokens served from a prefix cache.",
        ),
        def(
            CACHED_WRITE_TOKENS,
            "count",
            Reexec,
            true,
            "Prompt tokens written into a prefix cache for reuse.",
        ),
        def(
            REASONING_LOOPS,
            "count",
            Reexec,
            true,
            "Recurrent passes a recurrent-depth model executed.",
        ),
        def(
            IMAGE_TOKENS,
            "count",
            Payer,
            true,
            "Tokens an image input is worth under the model's image tokenization.",
        ),
        def(AUDIO_MS, "ms", Payer, true, "Audio consumed."),
        def(VIDEO_MS, "ms", Payer, true, "Video consumed."),
        def(
            PIXEL_STEPS,
            "pixel_steps",
            Payer,
            true,
            "Width times height times denoising steps times frames of a generation.",
        ),
        def(
            MEGAPIXELS,
            "mp",
            Payer,
            true,
            "Output pixels in millions, rounded up per output.",
        ),
        def(IMAGES, "count", Payer, true, "Images produced."),
        def(FRAMES, "count", Payer, true, "Frames produced or consumed."),
        def(VIDEO_OUT_MS, "ms", Payer, true, "Video produced."),
        def(
            CHARACTERS,
            "count",
            Payer,
            true,
            "Characters of text spoken.",
        ),
        def(AUDIO_OUT_MS, "ms", Payer, true, "Audio produced."),
        def(
            RERANK_PAIRS,
            "count",
            Payer,
            true,
            "Query and document pairs scored.",
        ),
        def(
            DECISION_QUESTIONS,
            "count",
            Payer,
            true,
            "Questions a decision model answered.",
        ),
        def(
            FORECAST_POINTS,
            "count",
            Payer,
            true,
            "Series times horizon steps emitted, every quantile at a step counted once.",
        ),
        def(
            TRAINED_TOKENS,
            "count",
            Reexec,
            true,
            "Tokens run forward and backward in training.",
        ),
        def(
            SIMULATED_MS,
            "ms",
            Payer,
            true,
            "Simulated world time produced.",
        ),
        def(
            SESSION_HOLD_MS,
            "ms",
            Provider,
            true,
            "Interactive session time booked.",
        ),
        def(
            SESSION_MS,
            "ms",
            Payer,
            true,
            "Wall-clock time a realtime session was open.",
        ),
        def(
            ACTION_CHUNKS,
            "count",
            Payer,
            true,
            "Chunks of actions a policy emitted.",
        ),
        def(
            CONTROL_STEPS,
            "count",
            Payer,
            true,
            "Control steps a policy drove at its stated rate.",
        ),
        def(
            ASSETS,
            "count",
            Payer,
            true,
            "Generated assets such as 3D meshes.",
        ),
        def(WORLDS, "count", Payer, true, "Generated persistent worlds."),
        def(
            ACCEL_MS,
            "ms",
            Provider,
            true,
            "Accelerator time on the stated hardware class.",
        ),
        def(REQUESTS, "count", Payer, true, "Requests served."),
        def(
            TTFT_MS,
            "ms",
            Payer,
            false,
            "Time from request to first output, as the caller measured it.",
        ),
        def(
            DECODE_MS,
            "ms",
            Payer,
            false,
            "Time from first to last output, as the caller measured it.",
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_ids_and_keys() {
        assert!(valid_unit_id("output_tokens"));
        assert!(valid_unit_id("energy_mwh"));
        assert!(!valid_unit_id("Output"));
        assert!(!valid_unit_id("1tokens"));
        assert!(!valid_unit_id(""));
        assert!(!valid_unit_id(&"a".repeat(MAX_UNIT_ID_LEN + 1)));
        assert_eq!(parse_key("output_tokens").unwrap(), ("output_tokens", None));
        assert_eq!(
            parse_key("input_tokens@ctx_gt_200k").unwrap(),
            ("input_tokens", Some("ctx_gt_200k"))
        );
        assert!(parse_key("input_tokens@").is_err());
        assert!(parse_key("input_tokens@a@b").is_err());
        assert!(parse_key("@tier").is_err());
        assert!(parse_key("input_tokens@4K").is_err());
        assert_eq!(key("video_out_ms", Some("4k")), "video_out_ms@4k");
    }

    #[test]
    fn genesis_units_are_valid_and_distinct() {
        let units = genesis_units();
        let mut ids = std::collections::BTreeSet::new();
        for u in &units {
            u.validate().unwrap();
            assert!(ids.insert(u.id.clone()), "duplicate {}", u.id);
        }
        assert!(units.iter().any(|u| u.id == unit::TTFT_MS && !u.billable));
    }

    #[test]
    fn a_bad_definition_is_refused() {
        let mut u = genesis_units().remove(0);
        u.scale = String::new();
        assert_eq!(u.validate(), Err(MeterError::BadScale));
        let mut u = genesis_units().remove(0);
        u.doc_hash = "00".into();
        assert_eq!(u.validate(), Err(MeterError::BadDocHash));
    }
}
