//! `/etc/tenzro/run.json` — the run spec the builder bakes into the rootfs.
//!
//! This is the contract between [`tenzro_machine_builder`] (which writes the
//! file) and the guest init (which reads it). It says *how to run the app*: the
//! command vector, the working directory, the loopback port the server listens
//! on, and the unprivileged user to drop to.

use serde::{Deserialize, Serialize};

/// Parsed `/etc/tenzro/run.json`.
///
/// Only `cmd` is required — an empty command is a fatal misconfiguration
/// (there would be nothing to run). The rest have sensible defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunSpec {
    /// argv of the app to exec, e.g. `["node", "server.js"]`. Never empty.
    pub cmd: Vec<String>,
    /// Working directory to `chdir` into before exec. Defaults to `/app`.
    #[serde(default = "default_cwd")]
    pub cwd: String,
    /// The loopback port the server listens on inside the guest. Mirrors the
    /// deployment's `internal_port`; surfaced to the app as `$PORT`. `None`
    /// means the app takes its port from the injected environment alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Unprivileged user name to drop to before exec (resolved against the
    /// rootfs `/etc/passwd`). `None` runs as root inside the guest — acceptable
    /// because the microVM is the isolation boundary, but a named user is
    /// preferred.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
}

fn default_cwd() -> String {
    "/app".to_string()
}

/// Errors that can arise parsing `run.json`.
#[derive(Debug)]
pub enum RunJsonError {
    /// The bytes were not valid JSON in the expected shape.
    Decode(String),
    /// `cmd` was present but empty — nothing to exec.
    EmptyCmd,
}

impl std::fmt::Display for RunJsonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunJsonError::Decode(e) => write!(f, "run.json decode: {e}"),
            RunJsonError::EmptyCmd => write!(f, "run.json: cmd must not be empty"),
        }
    }
}

impl std::error::Error for RunJsonError {}

/// Parse and validate `run.json` bytes.
pub fn parse_run_json(bytes: &[u8]) -> Result<RunSpec, RunJsonError> {
    let spec: RunSpec =
        serde_json::from_slice(bytes).map_err(|e| RunJsonError::Decode(e.to_string()))?;
    if spec.cmd.is_empty() || spec.cmd.iter().all(|s| s.trim().is_empty()) {
        return Err(RunJsonError::EmptyCmd);
    }
    Ok(spec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_spec_round_trips() {
        let json = br#"{"cmd":["node","server.js"],"cwd":"/srv","port":8080,"user":"app"}"#;
        let spec = parse_run_json(json).unwrap();
        assert_eq!(spec.cmd, vec!["node", "server.js"]);
        assert_eq!(spec.cwd, "/srv");
        assert_eq!(spec.port, Some(8080));
        assert_eq!(spec.user.as_deref(), Some("app"));
    }

    #[test]
    fn defaults_apply() {
        let spec = parse_run_json(br#"{"cmd":["./app"]}"#).unwrap();
        assert_eq!(spec.cwd, "/app", "cwd defaults to /app");
        assert_eq!(spec.port, None);
        assert_eq!(spec.user, None);
    }

    #[test]
    fn empty_cmd_is_rejected() {
        assert!(matches!(
            parse_run_json(br#"{"cmd":[]}"#),
            Err(RunJsonError::EmptyCmd)
        ));
        assert!(matches!(
            parse_run_json(br#"{"cmd":["  "]}"#),
            Err(RunJsonError::EmptyCmd)
        ));
    }

    #[test]
    fn garbage_is_a_decode_error() {
        assert!(matches!(
            parse_run_json(b"not json"),
            Err(RunJsonError::Decode(_))
        ));
        // Missing the required `cmd` field.
        assert!(matches!(
            parse_run_json(br#"{"cwd":"/app"}"#),
            Err(RunJsonError::Decode(_))
        ));
    }
}
