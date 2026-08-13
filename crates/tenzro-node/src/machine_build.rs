//! Node-side integration of the machine-class rootfs builder.
//!
//! `tenzro_machineDeploy` can carry an optional `build` object describing an app
//! *build context* — the built application (delivered as a content-addressed tar
//! blob), a base image, and a run spec — instead of a pre-built bootable image.
//! When present and the `machine-builder` feature is compiled in, the node:
//!
//! 1. fetches the app-context blob from the iroh store;
//! 2. unpacks it, resolves the base, and assembles a `rootfs.ext4` **rootlessly**
//!    (via [`tenzro_machine_builder`] → `mke2fs -d`), staging the static
//!    `tenzro-initagent` at `/sbin/tenzro-initagent` and the run spec at
//!    `/etc/tenzro/run.json`;
//! 3. publishes the finished `rootfs.ext4` as an iroh blob;
//! 4. returns its CAID, which becomes the deployment's `artifact_caid` — so the
//!    existing supervisor / `boot_firecracker` path boots it unchanged.
//!
//! Without the feature (or its `machine-builder-oci` extension for registry
//! pulls), the build path returns an honest, actionable error; a caller that
//! already has a bootable image keeps passing `artifact_caid` directly.

use serde::{Deserialize, Serialize};

/// The parsed `build` object from `tenzro_machineDeploy` params.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineBuildRequest {
    /// CAID (64 hex) of the app-context archive blob in the iroh store.
    pub app_caid: String,
    /// Whether the app-context archive is gzip-compressed (`.tar.gz`).
    #[serde(default = "default_true")]
    pub app_gzip: bool,
    /// Base image to overlay.
    #[serde(default)]
    pub base: BaseRef,
    /// How to run the app (becomes `/etc/tenzro/run.json`).
    pub run: RunJson,
    /// Target rootfs size (MiB) before the shrink. Clamped by the builder.
    #[serde(default)]
    pub size_mib: Option<u32>,
}

fn default_true() -> bool {
    true
}

/// Run spec mirror of `tenzro_initagent::RunSpec` for JSON-RPC parsing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunJson {
    pub cmd: Vec<String>,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub user: Option<String>,
}

/// Where the base filesystem comes from.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BaseRef {
    /// No base — a fully-static app that needs nothing from a distro.
    #[default]
    None,
    /// A pre-unpacked base tree on the node, keyed by name under the operator's
    /// bases directory (`TENZRO_MACHINE_BASES_DIR`).
    Dir { name: String },
    /// An OCI image pulled by pinned digest (needs `machine-builder-oci`).
    Oci {
        registry: String,
        repository: String,
        digest: String,
    },
}

/// Result of a successful build.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineBuildResult {
    /// CAID (64 hex) of the produced `rootfs.ext4` blob.
    pub rootfs_caid: String,
    /// Deterministic content hash of the build inputs (cache key).
    pub build_hash: String,
    /// Final image size in bytes.
    pub size_bytes: u64,
}

/// Env var: path to the static `tenzro-initagent` binary to stage in every
/// rootfs. Required for the build path.
pub const ENV_INITAGENT_BIN: &str = "TENZRO_INITAGENT_BIN";
/// Env var: directory holding pre-unpacked base trees, one subdir per base name.
pub const ENV_BASES_DIR: &str = "TENZRO_MACHINE_BASES_DIR";

/// Validate a CAID is 64 lowercase hex.
// Used by the feature-gated build impl and the tests; unused in a default build.
#[allow(dead_code)]
fn validate_caid(caid: &str) -> Result<(), String> {
    if caid.len() == 64 && caid.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        Ok(())
    } else {
        Err("app_caid must be 64 lowercase hex chars".into())
    }
}

#[cfg(feature = "machine-builder")]
mod imp {
    use super::*;
    use std::sync::Arc;
    use tenzro_iroh::IrohResolver as _;

    use crate::node::TenzroNode;

    /// Build a `rootfs.ext4` from the request and publish it as an iroh blob.
    pub async fn build_and_publish(
        node: &Arc<TenzroNode>,
        req: &MachineBuildRequest,
    ) -> Result<MachineBuildResult, String> {
        use tenzro_machine_builder::{BaseSource, BuildContext, OciRef, RunSpec};

        validate_caid(&req.app_caid)?;
        if req.run.cmd.is_empty() {
            return Err("build.run.cmd must not be empty".into());
        }

        // Resolver for fetch + publish.
        let resolver = node
            .iroh_resolver
            .clone()
            .ok_or("iroh transport not bound on this node")?;

        // The static init we stage into every rootfs.
        let initagent_bin = std::env::var(ENV_INITAGENT_BIN).map_err(|_| {
            format!("{ENV_INITAGENT_BIN} is not set (path to the static tenzro-initagent binary)")
        })?;
        let initagent_bin = std::path::PathBuf::from(initagent_bin);
        if !initagent_bin.is_file() {
            return Err(format!(
                "tenzro-initagent binary not found at {}",
                initagent_bin.display()
            ));
        }

        // Working area (auto-cleaned).
        let work = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;

        // 1. Fetch + unpack the app context.
        let app_uri = tenzro_iroh::TenzroUri::Blob {
            hash: req.app_caid.clone(),
            provider_hint: None,
        };
        let app_bytes = resolver
            .fetch_bytes(&app_uri)
            .await
            .map_err(|e| format!("fetch app context {}: {e}", req.app_caid))?;
        let app_dir = work.path().join("app-src");
        tenzro_machine_builder::archive::unpack_tar(&app_bytes, req.app_gzip, &app_dir)
            .map_err(|e| format!("unpack app context: {e}"))?;

        // 2. Resolve the base.
        let base = match &req.base {
            BaseRef::None => BaseSource::None,
            BaseRef::Dir { name } => {
                let bases = std::env::var(ENV_BASES_DIR).map_err(|_| {
                    format!("{ENV_BASES_DIR} is not set but build.base is a dir base")
                })?;
                // Guard the name so it can't escape the bases dir.
                if name.is_empty() || name.contains('/') || name.contains("..") {
                    return Err("build.base.name must be a bare directory name".into());
                }
                let dir = std::path::PathBuf::from(bases).join(name);
                if !dir.is_dir() {
                    return Err(format!("base '{name}' not found at {}", dir.display()));
                }
                BaseSource::Dir(dir)
            }
            BaseRef::Oci {
                registry,
                repository,
                digest,
            } => {
                #[cfg(feature = "machine-builder-oci")]
                {
                    BaseSource::Oci(OciRef {
                        registry: registry.clone(),
                        repository: repository.clone(),
                        digest: digest.clone(),
                    })
                }
                #[cfg(not(feature = "machine-builder-oci"))]
                {
                    let _ = (registry, repository, digest, std::marker::PhantomData::<OciRef>);
                    return Err(
                        "OCI base pull requires the node `machine-builder-oci` feature; \
                         use a dir base or a prebuilt artifact_caid instead"
                            .into(),
                    );
                }
            }
        };

        // 3. Build the rootfs.
        let run = RunSpec {
            cmd: req.run.cmd.clone(),
            cwd: req.run.cwd.clone().unwrap_or_else(|| "/app".to_string()),
            port: req.run.port,
            user: req.run.user.clone(),
        };
        let ctx = BuildContext {
            base,
            app_dir,
            initagent_bin,
            run,
            size_mib: req.size_mib.unwrap_or(tenzro_machine_builder::spec::DEFAULT_SIZE_MIB),
        };
        let out = tenzro_machine_builder::build_rootfs(&ctx, &work.path().join("build"))
            .await
            .map_err(|e| format!("rootfs build: {e}"))?;

        // 4. Publish the image as an iroh blob.
        let image = tokio::fs::read(&out.rootfs_path)
            .await
            .map_err(|e| format!("read built rootfs: {e}"))?;
        let size_bytes = out.size_bytes;
        let uri = resolver
            .publish_bytes(bytes::Bytes::from(image))
            .await
            .map_err(|e| format!("publish rootfs blob: {e}"))?;
        let rootfs_caid = match uri {
            tenzro_iroh::TenzroUri::Blob { hash, .. } => hash,
            other => return Err(format!("unexpected publish URI: {other}")),
        };

        Ok(MachineBuildResult {
            rootfs_caid,
            build_hash: out.build_hash,
            size_bytes,
        })
    }
}

#[cfg(feature = "machine-builder")]
pub use imp::build_and_publish;

/// Honest stub when the builder is not compiled in.
#[cfg(not(feature = "machine-builder"))]
pub async fn build_and_publish(
    _node: &std::sync::Arc<crate::node::TenzroNode>,
    _req: &MachineBuildRequest,
) -> Result<MachineBuildResult, String> {
    Err("machine-class rootfs builder is not compiled into this node \
         (rebuild with --features machine-builder). A prebuilt artifact_caid \
         still deploys directly."
        .into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_build_request() {
        let json = serde_json::json!({
            "app_caid": "aa".repeat(32),
            "app_gzip": true,
            "base": {"type": "dir", "name": "base-node20"},
            "run": {"cmd": ["node", "server.js"], "cwd": "/app", "port": 8080, "user": "app"},
            "size_mib": 256
        });
        let req: MachineBuildRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.run.cmd, vec!["node", "server.js"]);
        assert_eq!(req.run.port, Some(8080));
        assert!(matches!(req.base, BaseRef::Dir { .. }));
        assert_eq!(req.size_mib, Some(256));
    }

    #[test]
    fn base_defaults_to_none_and_gzip_true() {
        let json = serde_json::json!({
            "app_caid": "bb".repeat(32),
            "run": {"cmd": ["./app"]}
        });
        let req: MachineBuildRequest = serde_json::from_value(json).unwrap();
        assert!(matches!(req.base, BaseRef::None));
        assert!(req.app_gzip, "gzip defaults to true");
    }

    #[test]
    fn oci_base_parses() {
        let json = serde_json::json!({
            "app_caid": "cc".repeat(32),
            "base": {"type": "oci", "registry": "r.tenzro.network", "repository": "tenzro/base-static", "digest": "sha256:abc"},
            "run": {"cmd": ["./app"]}
        });
        let req: MachineBuildRequest = serde_json::from_value(json).unwrap();
        assert!(matches!(req.base, BaseRef::Oci { .. }));
    }

    #[test]
    fn caid_validation() {
        assert!(validate_caid(&"a".repeat(64)).is_ok());
        assert!(validate_caid("short").is_err());
        assert!(validate_caid(&"A".repeat(64)).is_err(), "uppercase rejected");
    }
}
