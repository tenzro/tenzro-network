//! Build inputs: what to put in the rootfs and how big it may get.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub use tenzro_initagent::RunSpec;

/// Default rootfs size budget (MiB) when the caller doesn't set one.
pub const DEFAULT_SIZE_MIB: u32 = 512;
/// Hard ceiling on the produced rootfs (MiB). The build fails closed above this
/// so a runaway build context can't fill the node's disk. Operators can lower
/// it but the code never exceeds it.
pub const MAX_SIZE_MIB: u32 = 8_192;
/// Hard ceiling on the *staged* content (bytes) before it is written to ext4.
/// Independent of the fs size so an over-large context is rejected before any
/// image is allocated.
pub const MAX_STAGE_BYTES: u64 = 4 * 1024 * 1024 * 1024; // 4 GiB

/// Where the base filesystem comes from.
#[derive(Debug, Clone)]
pub enum BaseSource {
    /// No base — the rootfs is only the app + init + run.json. Useful for a
    /// fully-static app that needs nothing from a distro.
    None,
    /// A pre-unpacked base root directory (its whole tree is copied in). This is
    /// the path used when the operator pre-fetches bases, and the target the
    /// OCI puller writes to.
    Dir(PathBuf),
    /// An OCI image reference pinned by digest, pulled + unpacked at build time.
    /// Only honored with the `oci` feature.
    Oci(OciRef),
}

/// A digest-pinned OCI image reference. Never a mutable tag — a machine rootfs
/// must be reproducible and a tag can move under us.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciRef {
    /// Registry host, e.g. `registry.tenzro.network`.
    pub registry: String,
    /// Repository, e.g. `tenzro/base-node20`.
    pub repository: String,
    /// `sha256:...` manifest digest. Required — no tag resolution.
    pub digest: String,
}

impl OciRef {
    /// The `registry/repo@sha256:...` reference string.
    pub fn reference(&self) -> String {
        format!("{}/{}@{}", self.registry, self.repository, self.digest)
    }

    /// Validate the digest is a pinned `sha256:<64 hex>`.
    pub fn validate(&self) -> Result<(), String> {
        let hex = self
            .digest
            .strip_prefix("sha256:")
            .ok_or("OCI digest must be sha256:<hex> (a tag is not allowed)")?;
        if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("OCI digest must be sha256 with 64 hex chars".into());
        }
        Ok(())
    }
}

/// A complete build request.
#[derive(Debug, Clone)]
pub struct BuildContext {
    /// Base filesystem source.
    pub base: BaseSource,
    /// The built application directory to overlay. Its contents are placed at
    /// `run.cwd` inside the rootfs (default `/app`).
    pub app_dir: PathBuf,
    /// Path to the static `tenzro-initagent` binary to install at
    /// `/sbin/tenzro-initagent`.
    pub initagent_bin: PathBuf,
    /// How to run the app; written to `/etc/tenzro/run.json`.
    pub run: RunSpec,
    /// Target rootfs size in MiB before the final `resize2fs -M` shrink.
    /// Clamped to `[64, MAX_SIZE_MIB]`.
    pub size_mib: u32,
}

impl BuildContext {
    /// Effective size, clamped to the allowed range.
    pub fn effective_size_mib(&self) -> u32 {
        self.size_mib.clamp(64, MAX_SIZE_MIB)
    }
}
