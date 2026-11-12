//! Which node a command talks to.
//!
//! One answer for every command: `--rpc <url>` before the command, else the
//! `TENZRO_RPC` environment variable, else the endpoint `tenzro setup`
//! saved, else this machine's node. A command that was given its own
//! `--rpc` keeps it; a command that left its flag at the local default takes
//! the answer above.

use std::sync::OnceLock;

/// The endpoint of a node on this machine, and the default of every
/// per-command `--rpc` flag.
pub const LOCAL_RPC: &str = "http://127.0.0.1:8545";

/// The public network's RPC endpoint.
pub const PUBLIC_RPC: &str = "https://rpc.tenzro.com";

static GLOBAL: OnceLock<Option<String>> = OnceLock::new();

/// Where the endpoint came from, for `tenzro doctor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Flag,
    Environment,
    Saved,
    Default,
}

impl Source {
    pub fn describe(self) -> &'static str {
        match self {
            Source::Flag => "--rpc",
            Source::Environment => "TENZRO_RPC",
            Source::Saved => "saved by tenzro setup",
            Source::Default => "default (this machine)",
        }
    }
}

/// Pure choice among the sources, in order of precedence. Empty strings are
/// treated as absent.
pub fn choose(flag: Option<&str>, env: Option<&str>, saved: Option<&str>) -> (String, Source) {
    let some = |v: Option<&str>| {
        v.map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    if let Some(v) = some(flag) {
        return (v, Source::Flag);
    }
    if let Some(v) = some(env) {
        return (v, Source::Environment);
    }
    if let Some(v) = some(saved) {
        return (v, Source::Saved);
    }
    (LOCAL_RPC.to_string(), Source::Default)
}

/// Record `--rpc` (the flag, or `TENZRO_RPC` through clap) for this process.
pub fn set_global(url: Option<String>) {
    let _ = GLOBAL.set(url.filter(|s| !s.trim().is_empty()));
}

/// The endpoint for this process and where it came from.
pub fn resolve() -> (String, Source) {
    let flag = GLOBAL.get().and_then(|v| v.as_deref());
    let env = std::env::var("TENZRO_RPC").ok();
    let saved = crate::config::load_config().endpoint;
    // The flag is `--rpc` or the environment through clap; when clap set it
    // from the environment the source is reported as the flag, which is
    // accurate enough for a person and exact in `choose`.
    choose(flag, env.as_deref(), saved.as_deref())
}

/// What a command should use for `url`. A command's own value wins; the
/// local default is replaced by the process-wide answer.
pub fn for_command(url: &str) -> String {
    if url.trim_end_matches('/') == LOCAL_RPC {
        resolve().0
    } else {
        url.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_beats_environment_beats_saved_beats_default() {
        assert_eq!(
            choose(Some("a"), Some("b"), Some("c")),
            ("a".into(), Source::Flag)
        );
        assert_eq!(
            choose(None, Some("b"), Some("c")),
            ("b".into(), Source::Environment)
        );
        assert_eq!(choose(None, None, Some("c")), ("c".into(), Source::Saved));
        assert_eq!(
            choose(None, None, None),
            (LOCAL_RPC.into(), Source::Default)
        );
    }

    #[test]
    fn blank_values_are_absent() {
        assert_eq!(choose(Some(" "), Some(""), None).1, Source::Default);
    }
}
