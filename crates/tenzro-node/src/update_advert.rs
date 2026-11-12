//! The software this node says it runs: its binary version, the SHA-256 of
//! the binary, and its update state. It goes into the signed endpoint record
//! (`tenzro_iroh::update_advert`) and into `tenzro_getNodeStatus`.
//!
//! Not consensus state. The update state comes from the files `tenzro update`
//! keeps (`tenzro_onboarding_types::update_state`).

use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tenzro_iroh::identity_transport::IdentityTransport;
use tenzro_iroh::update_advert::UpdateAdvert;
use tenzro_onboarding_types::update_state;

/// How often the update state is read again.
const REFRESH: Duration = Duration::from_secs(60);

/// The version of this binary.
pub const BINARY_VERSION: &str = env!("CARGO_PKG_VERSION");

/// SHA-256 of the executable this process started from, read once. Blocking:
/// it reads the whole file.
pub fn running_digest() -> Option<&'static str> {
    static DIGEST: OnceLock<Option<String>> = OnceLock::new();
    DIGEST
        .get_or_init(|| {
            // /proc/self/exe still opens the running image after the file was replaced.
            let path = if cfg!(target_os = "linux") { Some("/proc/self/exe".into()) } else { std::env::current_exe().ok() };
            match update_state::file_sha256(&path?) {
                Ok(h) => Some(h),
                Err(e) => {
                    tracing::warn!(error = %e, "could not hash the running binary; no software advert");
                    None
                }
            }
        })
        .as_deref()
}

/// The advert for a node running the binary with SHA-256 `digest`.
pub fn advert(data_dir: &Path, digest: &str) -> UpdateAdvert {
    UpdateAdvert {
        binary_version: BINARY_VERSION.to_string(),
        platform_digest: digest.to_string(),
        state: update_state::current_state(data_dir, digest),
    }
}

/// The `update` object of `tenzro_getNodeStatus`.
pub async fn status_json(data_dir: std::path::PathBuf) -> serde_json::Value {
    let digest = tokio::task::spawn_blocking(running_digest)
        .await
        .ok()
        .flatten();
    match digest {
        Some(d) => {
            let a = advert(&data_dir, d);
            serde_json::json!({
                "binary_version": a.binary_version,
                "platform_digest": a.platform_digest,
                "state": a.state.as_str(),
            })
        }
        None => {
            serde_json::json!({ "binary_version": BINARY_VERSION, "platform_digest": null, "state": null })
        }
    }
}

/// Keeps this node's record stating the software it runs. The first state is
/// declared as soon as the binary is hashed, then re-read every minute: a
/// record is re-signed only when the advert changed.
pub fn keep(transport: &Arc<IdentityTransport>, data_dir: std::path::PathBuf) {
    let transport = transport.clone();
    tokio::spawn(async move {
        let Some(digest) = tokio::task::spawn_blocking(running_digest)
            .await
            .ok()
            .flatten()
        else {
            return;
        };
        loop {
            let dir = data_dir.clone();
            if let Ok(a) = tokio::task::spawn_blocking(move || advert(&dir, digest)).await {
                transport.declare_update(a);
            }
            tokio::time::sleep(REFRESH).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_onboarding_types::update_state::UpdateState;

    #[test]
    fn the_advert_names_this_binary_and_its_state() {
        let d = tempfile::tempdir().unwrap();
        let a = advert(d.path(), &"cd".repeat(32));
        assert_eq!(a.binary_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(a.state, UpdateState::Running);
        std::fs::create_dir_all(d.path().join("upgrade")).unwrap();
        std::fs::write(update_state::staged_binary_path(d.path()), b"another build").unwrap();
        assert_eq!(
            advert(d.path(), &"cd".repeat(32)).state,
            UpdateState::Staged
        );
    }

    #[test]
    fn the_running_binary_hashes_to_a_digest_an_advert_accepts() {
        let d = running_digest().expect("the test binary can be read");
        assert_eq!(d.len(), 64);
    }
}
