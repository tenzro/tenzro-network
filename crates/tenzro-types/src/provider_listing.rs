//! What a provider tells discovery about itself beyond its models: a coarse
//! region, and the live load of each model it serves.
//!
//! A region is deliberately coarse: a country (ISO 3166-1 alpha-2, e.g.
//! `DE`) or a wide region (e.g. `europe`), never a city, site or address. A
//! node may omit it.

use serde::{Deserialize, Serialize};

/// The wide regions a provider may declare instead of a country.
pub const WIDE_REGIONS: &[&str] = &[
    "africa",
    "asia",
    "europe",
    "latin-america",
    "middle-east",
    "north-america",
    "oceania",
];

/// The canonical form of a coarse region: an upper-case ISO 3166-1 alpha-2
/// country code or one of [`WIDE_REGIONS`]. Anything finer, or anything
/// else, is refused.
pub fn coarse_region(s: &str) -> Result<String, String> {
    let t = s.trim();
    if t.len() == 2 && t.chars().all(|c| c.is_ascii_alphabetic()) {
        return Ok(t.to_ascii_uppercase());
    }
    let lower = t.to_ascii_lowercase();
    if WIDE_REGIONS.contains(&lower.as_str()) {
        return Ok(lower);
    }
    Err(format!(
        "region {s:?} is neither a two-letter country code nor one of {}",
        WIDE_REGIONS.join(", ")
    ))
}

/// Where a served model stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelServingState {
    /// Not loaded; the first request pays the load.
    Cold,
    /// Loading; requests wait for it.
    Warming,
    /// Loaded and serving.
    Warm,
    /// Being unloaded.
    Evicting,
}

/// The live load of one served model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelLoad {
    /// The model.
    pub model_id: String,
    /// Where it stands.
    pub state: ModelServingState,
    /// Requests admitted and not yet finished.
    pub in_flight: u32,
    /// Most requests it admits at once.
    pub max_concurrent: u32,
    /// Requests waiting for it to finish loading.
    pub queue_depth: u32,
    /// Estimated time until it is loaded, ms, while warming.
    pub warm_eta_ms: Option<u64>,
}

impl ModelLoad {
    /// Requests it can admit now.
    pub fn available(&self) -> u32 {
        self.max_concurrent.saturating_sub(self.in_flight)
    }
}

/// Most model entries one heartbeat carries.
pub const MAX_MODEL_LOADS: usize = 256;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_countries_and_wide_regions_are_coarse() {
        assert_eq!(coarse_region(" de ").unwrap(), "DE");
        assert_eq!(coarse_region("Europe").unwrap(), "europe");
        for fine in ["us-east-1", "frankfurt", "DE-BY", "eu-west", ""] {
            assert!(coarse_region(fine).is_err(), "{fine} is not coarse");
        }
    }
}
