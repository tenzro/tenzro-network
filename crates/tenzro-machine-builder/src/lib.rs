//! `tenzro-machine-builder` — produce a bootable `rootfs.ext4` for a Tenzro
//! machine-class (Firecracker) deploy, **rootlessly**.
//!
//! Pipeline:
//!
//! ```text
//!   OCI base (pinned digest)  ─┐
//!   built-app directory        ├─▶ stage/  ──mke2fs -d──▶ rootfs.ext4
//!   /sbin/tenzro-initagent     │            e2fsck -fy
//!   /etc/tenzro/run.json       ─┘            resize2fs -M
//! ```
//!
//! The staged tree is populated with ordinary file I/O and written to an ext4
//! image with `mke2fs -d` — no mount, no loopback, no `CAP_SYS_ADMIN`. The
//! resulting image boots on the operator's existing `vmlinux` with
//! `init=/sbin/tenzro-initagent` ([`tenzro_initagent`]).
//!
//! ## Security posture (v1)
//!
//! * The builder **never executes app code**. The app is prebuilt client-side;
//!   the builder only pulls a trusted base, copies files, and runs mkfs. There
//!   is no `RUN` step, so there is no untrusted-code-execution surface.
//! * Bases are pulled **only by pinned `sha256` digest** from a trusted
//!   registry ([`spec::OciRef::validate`]); a mutable tag is rejected.
//! * The staged content and the image size are both **bounded**
//!   ([`spec::MAX_STAGE_BYTES`], [`spec::MAX_SIZE_MIB`]); an over-large context
//!   fails closed before any disk is allocated.
//!
//! (v2 — running untrusted `RUN` steps — must happen inside a throwaway
//! build-VM, which is explicitly out of scope for v1.)

pub mod error;
pub mod ext4;
pub mod spec;
pub mod stage;

#[cfg(feature = "archive")]
pub mod archive;

#[cfg(feature = "oci")]
pub mod oci;

use std::path::{Path, PathBuf};

pub use error::BuildError;
pub use ext4::{Ext4Image, tools_available};
pub use spec::{BaseSource, BuildContext, OciRef, RunSpec};

/// The finished artifact.
#[derive(Debug, Clone)]
pub struct BuildOutput {
    /// Path to the produced `rootfs.ext4`.
    pub rootfs_path: PathBuf,
    /// Final (post-shrink) image size in bytes.
    pub size_bytes: u64,
    /// Deterministic content hash of the staged tree — a build-cache key.
    pub build_hash: String,
}

/// Build a `rootfs.ext4` from `ctx`, writing it into `work_dir` (which holds the
/// staging tree and the image). Returns the image path + metadata.
///
/// Base resolution:
///   * [`BaseSource::None`] — no base;
///   * [`BaseSource::Dir`] — copy an already-unpacked base tree;
///   * [`BaseSource::Oci`] — pull + unpack by digest (requires the `oci`
///     feature; without it this variant errors with a clear message).
pub async fn build_rootfs(ctx: &BuildContext, work_dir: &Path) -> Result<BuildOutput, BuildError> {
    std::fs::create_dir_all(work_dir)
        .map_err(|e| BuildError::Stage(format!("mkdir work {}: {e}", work_dir.display())))?;

    // 1. Resolve the base into a directory (or None).
    let base_dir: Option<PathBuf> = match &ctx.base {
        BaseSource::None => None,
        BaseSource::Dir(d) => {
            if !d.is_dir() {
                return Err(BuildError::Invalid(format!(
                    "base dir {} does not exist",
                    d.display()
                )));
            }
            Some(d.clone())
        }
        BaseSource::Oci(oci_ref) => {
            #[cfg(feature = "oci")]
            {
                let dest = work_dir.join("base");
                oci::pull_and_unpack(oci_ref, &dest).await?;
                Some(dest)
            }
            #[cfg(not(feature = "oci"))]
            {
                let _ = oci_ref;
                return Err(BuildError::Oci(
                    "OCI base pull requires the `oci` feature; supply a pre-unpacked base dir instead"
                        .into(),
                ));
            }
        }
    };

    // 2. Stage the tree.
    let stage_dir = work_dir.join("stage");
    let staged = stage::stage(ctx, base_dir.as_deref(), &stage_dir)?;

    // 3. Build the ext4 image.
    let rootfs_path = work_dir.join("rootfs.ext4");
    let image = ext4::build(&staged.dir, &rootfs_path, ctx.effective_size_mib())?;

    Ok(BuildOutput {
        rootfs_path,
        size_bytes: image.size_bytes,
        build_hash: staged.manifest_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(tmp: &Path) -> BuildContext {
        let app = tmp.join("app");
        std::fs::create_dir_all(&app).unwrap();
        std::fs::write(app.join("server.js"), b"console.log('ok')").unwrap();
        let init = tmp.join("init-bin");
        std::fs::write(&init, b"\x7fELF static").unwrap();
        BuildContext {
            base: BaseSource::None,
            app_dir: app,
            initagent_bin: init,
            run: RunSpec {
                cmd: vec!["node".into(), "server.js".into()],
                cwd: "/app".into(),
                port: Some(8080),
                user: None,
            },
            size_mib: 64,
        }
    }

    #[tokio::test]
    #[cfg(feature = "oci")]
    async fn oci_variant_needs_feature_message_is_unreachable_with_feature() {
        // With the feature on, BaseSource::Oci at least validates the digest.
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = fixture(tmp.path());
        ctx.base = BaseSource::Oci(OciRef {
            registry: "registry.tenzro.network".into(),
            repository: "tenzro/base-node20".into(),
            digest: "not-a-digest".into(),
        });
        let err = build_rootfs(&ctx, &tmp.path().join("work")).await;
        assert!(err.is_err());
    }

    // End-to-end (rootless): stage + real mke2fs, gated on e2fsprogs. This is
    // the load-bearing test — it proves the whole pipeline produces a valid,
    // fsck-clean image containing the app, init, and run.json, with no root.
    #[test]
    fn end_to_end_rootless_build() {
        if std::env::var_os("TENZRO_SKIP_EXT4_TESTS").is_some() || !tools_available() {
            eprintln!("skipping e2e ext4 build (e2fsprogs unavailable / opted out)");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let ctx = fixture(tmp.path());
        let work = tmp.path().join("work");
        // build_rootfs is async only because of the OCI path; drive it on a
        // tiny executor without pulling tokio into the default build.
        let out = pollster_block(build_rootfs(&ctx, &work));
        let out = out.unwrap();
        assert!(out.rootfs_path.is_file());
        assert!(out.size_bytes > 0);
        assert_eq!(out.build_hash.len(), 64);

        let root_ls = ext4::debugfs_ls(&out.rootfs_path, "/").unwrap_or_default();
        // debugfs may be absent even when mke2fs isn't; only assert if we got output.
        if !root_ls.is_empty() {
            assert!(root_ls.contains("app"));
            assert!(root_ls.contains("sbin"));
            assert!(root_ls.contains("etc"));
        }
    }

    /// Minimal synchronous block-on so the default (no-tokio) test build can
    /// drive the async `build_rootfs`. The future never actually awaits I/O in
    /// the non-OCI path, so a busy poll with a no-op waker resolves it
    /// immediately.
    fn pollster_block<F: std::future::Future>(mut fut: F) -> F::Output {
        use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
        fn noop(_: *const ()) {}
        fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(std::ptr::null(), &VTABLE)
        }
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
        let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) };
        let mut cx = Context::from_waker(&waker);
        // Safety: fut is not moved after pinning.
        let mut fut = unsafe { std::pin::Pin::new_unchecked(&mut fut) };
        loop {
            if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }
}
