//! The network phase that decides whether the "apply to the Tenzro team"
//! message is shown.

use super::foundation_config::default_phase;

/// Which stage the network's staking is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Initial phase: the Tenzro team reviews applications and funds the stake
    /// of approved applicants.
    Foundation,
    /// Open staking: anyone holding the TNZO may bond. No application message.
    OpenStake,
}

impl Phase {
    pub fn parse(s: &str) -> Option<Phase> {
        match s.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "foundation" | "initial" | "team" => Some(Phase::Foundation),
            "open-stake" | "openstake" | "open" => Some(Phase::OpenStake),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Phase::Foundation => "foundation",
            Phase::OpenStake => "open-stake",
        }
    }

    /// Pure resolution: the environment wins, then the config, then the
    /// compiled default. An unrecognised value is ignored, not trusted.
    pub fn resolve(env: Option<&str>, config: Option<&str>) -> Phase {
        env.and_then(Phase::parse)
            .or_else(|| config.and_then(Phase::parse))
            .unwrap_or_else(default_phase)
    }

    /// Read `TENZRO_PHASE` and the CLI config.
    pub fn current() -> Phase {
        Phase::resolve(
            std::env::var("TENZRO_PHASE").ok().as_deref(),
            crate::config::load_config().onboarding_phase.as_deref(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_beats_config_beats_default() {
        assert_eq!(Phase::resolve(None, None), default_phase());
        assert_eq!(Phase::resolve(None, Some("open-stake")), Phase::OpenStake);
        assert_eq!(
            Phase::resolve(Some("foundation"), Some("open-stake")),
            Phase::Foundation
        );
        assert_eq!(
            Phase::resolve(Some("open_stake"), Some("foundation")),
            Phase::OpenStake
        );
    }

    #[test]
    fn junk_is_ignored() {
        assert_eq!(
            Phase::resolve(Some("banana"), Some("open-stake")),
            Phase::OpenStake
        );
        assert_eq!(Phase::resolve(Some("banana"), None), default_phase());
    }
}
