//! Assemble the staging directory that becomes the rootfs.
//!
//! Everything here is ordinary userspace file I/O — no root, no mount, no
//! privileged syscall — which is what makes the whole builder rootless. The
//! staging tree is later handed to `mke2fs -d` ([`crate::ext4`]).

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::error::BuildError;
use crate::spec::{BuildContext, MAX_STAGE_BYTES, RunSpec};

/// Result of staging: the directory to feed to `mke2fs -d`, its total byte
/// size, and a content manifest hash for build-cache keying.
#[derive(Debug, Clone)]
pub struct Staged {
    pub dir: PathBuf,
    pub total_bytes: u64,
    /// SHA-256 over the (sorted) file manifest + run.json + initagent — a
    /// deterministic key for the produced rootfs independent of fs timestamps.
    pub manifest_hash: String,
}

/// Copy a directory tree recursively, returning the bytes copied. Symlinks are
/// copied as symlinks; special files are skipped. Enforces `MAX_STAGE_BYTES`
/// across the whole staging operation via the running `budget`.
fn copy_tree(src: &Path, dst: &Path, budget: &mut u64) -> Result<u64, BuildError> {
    let mut copied = 0u64;
    std::fs::create_dir_all(dst)
        .map_err(|e| BuildError::Stage(format!("mkdir {}: {e}", dst.display())))?;
    for entry in std::fs::read_dir(src)
        .map_err(|e| BuildError::Stage(format!("read_dir {}: {e}", src.display())))?
    {
        let entry = entry.map_err(|e| BuildError::Stage(e.to_string()))?;
        let ft = entry.file_type().map_err(|e| BuildError::Stage(e.to_string()))?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if ft.is_dir() {
            copied += copy_tree(&from, &to, budget)?;
        } else if ft.is_symlink() {
            let target = std::fs::read_link(&from)
                .map_err(|e| BuildError::Stage(format!("readlink {}: {e}", from.display())))?;
            // Replace any existing entry (a base may ship the same path).
            let _ = std::fs::remove_file(&to);
            symlink(&target, &to)?;
        } else if ft.is_file() {
            let len = entry.metadata().map(|m| m.len()).unwrap_or(0);
            *budget = budget
                .checked_sub(len)
                .ok_or(BuildError::TooLarge(MAX_STAGE_BYTES))?;
            std::fs::copy(&from, &to)
                .map_err(|e| BuildError::Stage(format!("copy {}: {e}", from.display())))?;
            copied += len;
        }
        // Other file types (fifo/socket/device) are intentionally skipped.
    }
    Ok(copied)
}

#[cfg(unix)]
fn symlink(target: &Path, link: &Path) -> Result<(), BuildError> {
    std::os::unix::fs::symlink(target, link)
        .map_err(|e| BuildError::Stage(format!("symlink {}: {e}", link.display())))
}

#[cfg(not(unix))]
fn symlink(_target: &Path, _link: &Path) -> Result<(), BuildError> {
    Err(BuildError::Stage("symlinks require a unix host".into()))
}

/// Make a file executable (0755). No-op on non-unix.
fn make_executable(path: &Path) -> Result<(), BuildError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o755);
        std::fs::set_permissions(path, perms)
            .map_err(|e| BuildError::Stage(format!("chmod {}: {e}", path.display())))?;
    }
    let _ = path;
    Ok(())
}

/// Serialize the run spec the way the guest expects at `/etc/tenzro/run.json`.
pub fn run_json_bytes(run: &RunSpec) -> Result<Vec<u8>, BuildError> {
    serde_json::to_vec_pretty(run).map_err(|e| BuildError::Stage(format!("run.json encode: {e}")))
}

/// Build the staging tree from a build context, into `stage_dir` (created).
///
/// Layout produced:
///   * base tree (if any) copied in first, so app/init/run.json overlay it;
///   * `app_dir` contents placed at `run.cwd` (default `/app`);
///   * the init binary at `/sbin/tenzro-initagent` (0755);
///   * `/etc/tenzro/run.json`.
pub fn stage(ctx: &BuildContext, base_dir: Option<&Path>, stage_dir: &Path) -> Result<Staged, BuildError> {
    if !ctx.app_dir.is_dir() {
        return Err(BuildError::Stage(format!(
            "app_dir {} is not a directory",
            ctx.app_dir.display()
        )));
    }
    if !ctx.initagent_bin.is_file() {
        return Err(BuildError::Stage(format!(
            "initagent binary {} not found",
            ctx.initagent_bin.display()
        )));
    }

    let mut budget = MAX_STAGE_BYTES;
    std::fs::create_dir_all(stage_dir)
        .map_err(|e| BuildError::Stage(format!("mkdir {}: {e}", stage_dir.display())))?;

    // 1. Base tree.
    if let Some(base) = base_dir {
        copy_tree(base, stage_dir, &mut budget)?;
    }

    // 2. App into run.cwd.
    let cwd = ctx.run.cwd.trim_start_matches('/');
    let app_dst = if cwd.is_empty() {
        stage_dir.to_path_buf()
    } else {
        stage_dir.join(cwd)
    };
    copy_tree(&ctx.app_dir, &app_dst, &mut budget)?;

    // 3. Init binary.
    let sbin = stage_dir.join("sbin");
    std::fs::create_dir_all(&sbin)
        .map_err(|e| BuildError::Stage(format!("mkdir {}: {e}", sbin.display())))?;
    let init_dst = sbin.join("tenzro-initagent");
    std::fs::copy(&ctx.initagent_bin, &init_dst)
        .map_err(|e| BuildError::Stage(format!("copy initagent: {e}")))?;
    make_executable(&init_dst)?;

    // 4. run.json.
    let etc = stage_dir.join("etc").join("tenzro");
    std::fs::create_dir_all(&etc)
        .map_err(|e| BuildError::Stage(format!("mkdir {}: {e}", etc.display())))?;
    let run_bytes = run_json_bytes(&ctx.run)?;
    std::fs::write(etc.join("run.json"), &run_bytes)
        .map_err(|e| BuildError::Stage(format!("write run.json: {e}")))?;

    // Manifest hash + total size over the final tree.
    let (manifest_hash, total_bytes) = manifest(stage_dir, &run_bytes, &ctx.initagent_bin)?;
    Ok(Staged {
        dir: stage_dir.to_path_buf(),
        total_bytes,
        manifest_hash,
    })
}

/// Deterministic content hash + total size of the staged tree.
fn manifest(root: &Path, run_bytes: &[u8], initagent: &Path) -> Result<(String, u64), BuildError> {
    let mut files: Vec<(String, u64, [u8; 32])> = Vec::new();
    collect(root, root, &mut files)?;
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let total = files.iter().map(|(_, len, _)| *len).sum();

    let mut hasher = Sha256::new();
    for (rel, len, digest) in &files {
        hasher.update(rel.as_bytes());
        hasher.update(len.to_le_bytes());
        hasher.update(digest);
    }
    hasher.update(b"run.json");
    hasher.update(Sha256::digest(run_bytes));
    if let Ok(bytes) = std::fs::read(initagent) {
        hasher.update(b"initagent");
        hasher.update(Sha256::digest(&bytes));
    }
    Ok((hex::encode(hasher.finalize()), total))
}

fn collect(root: &Path, dir: &Path, out: &mut Vec<(String, u64, [u8; 32])>) -> Result<(), BuildError> {
    for entry in std::fs::read_dir(dir).map_err(|e| BuildError::Stage(e.to_string()))? {
        let entry = entry.map_err(|e| BuildError::Stage(e.to_string()))?;
        let path = entry.path();
        let ft = entry.file_type().map_err(|e| BuildError::Stage(e.to_string()))?;
        if ft.is_dir() {
            collect(root, &path, out)?;
        } else if ft.is_file() {
            let rel = path.strip_prefix(root).unwrap_or(&path).to_string_lossy().to_string();
            let bytes = std::fs::read(&path).map_err(|e| BuildError::Stage(e.to_string()))?;
            let digest: [u8; 32] = Sha256::digest(&bytes).into();
            out.push((rel, bytes.len() as u64, digest));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::{BaseSource, RunSpec};

    fn ctx(tmp: &Path) -> (BuildContext, PathBuf) {
        let app = tmp.join("app");
        std::fs::create_dir_all(&app).unwrap();
        std::fs::write(app.join("server.js"), b"console.log('hi')").unwrap();
        std::fs::create_dir_all(app.join("public")).unwrap();
        std::fs::write(app.join("public").join("index.html"), b"<h1>hi</h1>").unwrap();

        let init = tmp.join("tenzro-initagent");
        std::fs::write(&init, b"\x7fELF fake static binary").unwrap();

        let ctx = BuildContext {
            base: BaseSource::None,
            app_dir: app,
            initagent_bin: init,
            run: RunSpec {
                cmd: vec!["node".into(), "server.js".into()],
                cwd: "/app".into(),
                port: Some(8080),
                user: None,
            },
            size_mib: 128,
        };
        (ctx, tmp.join("stage"))
    }

    #[test]
    fn stages_app_init_and_run_json() {
        let tmp = tempfile::tempdir().unwrap();
        let (c, stage_dir) = ctx(tmp.path());
        let staged = stage(&c, None, &stage_dir).unwrap();

        assert!(stage_dir.join("app/server.js").is_file());
        assert!(stage_dir.join("app/public/index.html").is_file());
        assert!(stage_dir.join("sbin/tenzro-initagent").is_file());
        assert!(stage_dir.join("etc/tenzro/run.json").is_file());
        assert!(staged.total_bytes > 0);
        assert_eq!(staged.manifest_hash.len(), 64);
    }

    #[test]
    fn run_json_round_trips_through_guest_parser() {
        let tmp = tempfile::tempdir().unwrap();
        let (c, stage_dir) = ctx(tmp.path());
        stage(&c, None, &stage_dir).unwrap();
        let bytes = std::fs::read(stage_dir.join("etc/tenzro/run.json")).unwrap();
        // The guest init must be able to parse exactly what we wrote.
        let parsed = tenzro_initagent::parse_run_json(&bytes).unwrap();
        assert_eq!(parsed.cmd, vec!["node", "server.js"]);
        assert_eq!(parsed.port, Some(8080));
    }

    #[test]
    fn base_is_overlaid_by_app() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("base");
        std::fs::create_dir_all(base.join("bin")).unwrap();
        std::fs::write(base.join("bin/sh"), b"shell").unwrap();
        let (c, stage_dir) = ctx(tmp.path());
        stage(&c, Some(&base), &stage_dir).unwrap();
        assert!(stage_dir.join("bin/sh").is_file(), "base tree copied in");
        assert!(stage_dir.join("app/server.js").is_file(), "app overlaid");
    }

    #[test]
    fn missing_app_dir_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let (mut c, stage_dir) = ctx(tmp.path());
        c.app_dir = tmp.path().join("does-not-exist");
        assert!(stage(&c, None, &stage_dir).is_err());
    }

    #[test]
    fn manifest_hash_is_stable_across_runs() {
        let tmp = tempfile::tempdir().unwrap();
        let (c, _) = ctx(tmp.path());
        let h1 = stage(&c, None, &tmp.path().join("s1")).unwrap().manifest_hash;
        let h2 = stage(&c, None, &tmp.path().join("s2")).unwrap().manifest_hash;
        assert_eq!(h1, h2, "same inputs -> same hash");
    }
}
