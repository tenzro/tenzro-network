//! Final environment assembly for the app process.
//!
//! Precedence (lowest to highest):
//!   1. a minimal base (`PATH`) so common binaries resolve even in a bare rootfs;
//!   2. plaintext env from MMDS (`env`);
//!   3. guest-unsealed `sealed_env` (when used);
//!   4. `PORT`, set from `run.json`'s `port` (the deployment `internal_port`) so
//!      the app binds the port ingress bridges to — unless the injected env
//!      already set `PORT`, which the operator's explicit value wins over.

use std::collections::BTreeMap;

/// The default `PATH` for a machine guest. Kept small; the base image adds its
/// own via MMDS or the app's own env if it needs more.
pub const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Assemble the environment the app is exec'd with.
///
/// `mmds_env` is the plaintext map, `unsealed` the guest-unsealed secrets (empty
/// in the default node flow), and `port` the run-spec port. Later sources
/// override earlier ones by key; `PORT` is only injected if nothing already set
/// it.
pub fn assemble_env(
    mmds_env: &BTreeMap<String, String>,
    unsealed: &[(String, String)],
    port: Option<u16>,
) -> Vec<(String, String)> {
    let mut merged: BTreeMap<String, String> = BTreeMap::new();
    merged.insert("PATH".to_string(), DEFAULT_PATH.to_string());
    for (k, v) in mmds_env {
        merged.insert(k.clone(), v.clone());
    }
    for (k, v) in unsealed {
        merged.insert(k.clone(), v.clone());
    }
    if let Some(p) = port {
        merged.entry("PORT".to_string()).or_insert_with(|| p.to_string());
    }
    merged.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn get<'a>(env: &'a [(String, String)], key: &str) -> Option<&'a str> {
        env.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    #[test]
    fn base_path_always_present() {
        let env = assemble_env(&BTreeMap::new(), &[], None);
        assert_eq!(get(&env, "PATH"), Some(DEFAULT_PATH));
    }

    #[test]
    fn mmds_overrides_base_and_port_is_injected() {
        let env = assemble_env(&map(&[("LOG", "debug")]), &[], Some(8080));
        assert_eq!(get(&env, "LOG"), Some("debug"));
        assert_eq!(get(&env, "PORT"), Some("8080"));
    }

    #[test]
    fn sealed_overrides_plaintext() {
        let env = assemble_env(
            &map(&[("API_KEY", "placeholder")]),
            &[("API_KEY".to_string(), "real-secret".to_string())],
            None,
        );
        assert_eq!(get(&env, "API_KEY"), Some("real-secret"));
    }

    #[test]
    fn explicit_port_env_wins_over_run_spec() {
        let env = assemble_env(&map(&[("PORT", "3000")]), &[], Some(8080));
        assert_eq!(get(&env, "PORT"), Some("3000"), "operator PORT beats run.json");
    }
}
