//! Every value in the initial-phase onboarding flow that someone at the
//! Tenzro team has to fill in or flip later lives in ONE file:
//! `foundation_config.json`, next to this one. Nothing else in the CLI or the
//! wallet app spells a contact channel, the join link, the reply-time text,
//! the status endpoint or the default phase. The wallet app imports the same
//! JSON file.
//!
//! To change a contact channel, the join link or the reply time: edit the JSON.
//! To end the initial phase: set `"default_phase": "open-stake"` (or, per
//! machine, `TENZRO_PHASE=open-stake` / `onboarding_phase` in
//! `~/.tenzro/config.json`). The "apply and the Tenzro team will fund you"
//! message then disappears everywhere, `tenzro doctor` included, because they
//! all render through `onboarding::message`.

use std::sync::LazyLock;

use serde::Deserialize;

use super::phase::Phase;

#[derive(Debug, Deserialize)]
struct Raw {
    foundation_contact_channels: Vec<(String, String)>,
    join_link: String,
    expected_reply_time: String,
    status_endpoint_base: String,
    default_phase: String,
}

static RAW: LazyLock<Raw> = LazyLock::new(|| {
    serde_json::from_str(include_str!("foundation_config.json"))
        .expect("onboarding/foundation_config.json is valid (checked by a unit test)")
});

/// How to reach the Tenzro team: `(label, value)` rows, printed in order.
///
/// These are the channels the team answers on; a row is listed only while
/// someone reads it.
pub static FOUNDATION_CONTACT_CHANNELS: LazyLock<Vec<(String, String)>> =
    LazyLock::new(|| RAW.foundation_contact_channels.clone());

/// Where a person applies. Overridable per machine with `TENZRO_JOIN_LINK`
/// (or `onboarding_join_link` in the CLI config).
pub fn join_link() -> &'static str {
    &RAW.join_link
}

/// What applicants are told about when to expect an answer. It is printed
/// after "Expected reply:", so it reads as the end of that sentence.
pub fn expected_reply_time() -> &'static str {
    &RAW.expected_reply_time
}

/// Base URL of the website's application-status endpoint (see
/// `onboarding::status_source`). Overridable with `TENZRO_JOIN_STATUS_URL`.
/// While the website does not answer on it, the CLI treats the lookup as
/// unavailable and works from the chain alone.
pub fn status_endpoint_base() -> &'static str {
    &RAW.status_endpoint_base
}

/// The phase when neither `TENZRO_PHASE` nor the config names one.
pub fn default_phase() -> Phase {
    Phase::parse(&RAW.default_phase).expect("default_phase is foundation or open-stake (unit test)")
}

/// Render [`FOUNDATION_CONTACT_CHANNELS`] as `Label: value` strings.
pub fn contact_lines() -> Vec<String> {
    FOUNDATION_CONTACT_CHANNELS
        .iter()
        .map(|(l, v)| format!("{l}: {v}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_file_parses_and_names_at_least_one_channel() {
        assert!(!FOUNDATION_CONTACT_CHANNELS.is_empty());
        assert!(
            !join_link().is_empty()
                && !expected_reply_time().is_empty()
                && !status_endpoint_base().is_empty()
        );
        let _ = default_phase();
    }

    #[test]
    fn no_shipped_value_is_a_stand_in() {
        let mut values: Vec<&str> = FOUNDATION_CONTACT_CHANNELS
            .iter()
            .map(|(_, v)| v.as_str())
            .collect();
        values.extend([join_link(), expected_reply_time(), status_endpoint_base()]);
        for v in values {
            assert!(
                !v.contains("PLACEHOLDER") && !v.contains(".invalid"),
                "{v} is not a real value"
            );
        }
    }
}
