//! Rootless ext4 image construction via e2fsprogs.
//!
//! The whole point: `mke2fs -d <dir>` populates a fresh filesystem image from a
//! directory tree **without ever mounting it** and **without root** — no
//! loopback device, no `CAP_SYS_ADMIN`, no `mount(2)`. That is what lets the
//! node build a bootable rootfs as an unprivileged process. We then:
//!   * `e2fsck -fy` — force a full check and auto-fix, so a subtly malformed
//!     image never reaches a guest;
//!   * `resize2fs -M` — shrink to the minimum that holds the content, so the
//!     staged blob is as small as possible (the microVM overlay can grow it).

use std::path::Path;
use std::process::Command;

use crate::error::BuildError;

/// The e2fsprogs tools the builder shells out to.
pub const REQUIRED_TOOLS: &[&str] = &["mke2fs", "e2fsck", "resize2fs"];

/// Whether all required tools resolve on `PATH`. Callers use this to skip the
/// real-fs path (and tests to skip cleanly) when e2fsprogs isn't installed.
pub fn tools_available() -> bool {
    REQUIRED_TOOLS.iter().all(|t| which(t).is_some())
}

fn which(tool: &str) -> Option<std::path::PathBuf> {
    // e2fsprogs commonly lives in /sbin and /usr/sbin, which aren't always on a
    // service PATH; check those explicitly in addition to PATH.
    let mut dirs: Vec<std::path::PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    for extra in ["/sbin", "/usr/sbin", "/usr/local/sbin"] {
        dirs.push(std::path::PathBuf::from(extra));
    }
    dirs.into_iter().map(|d| d.join(tool)).find(|p| p.is_file())
}

fn tool_cmd(tool: &str) -> Result<Command, BuildError> {
    let path = which(tool).ok_or_else(|| BuildError::MissingTool(tool.to_string()))?;
    Ok(Command::new(path))
}

fn run(mut cmd: Command, ctx: &str) -> Result<(), BuildError> {
    let out = cmd
        .output()
        .map_err(|e| BuildError::Ext4(format!("{ctx}: spawn: {e}")))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        return Err(BuildError::Ext4(format!(
            "{ctx}: {} (stderr: {}; stdout: {})",
            out.status,
            stderr.trim(),
            stdout.trim()
        )));
    }
    Ok(())
}

/// Metadata about a produced rootfs image.
#[derive(Debug, Clone)]
pub struct Ext4Image {
    pub size_bytes: u64,
}

/// Build `out_path` as an ext4 image populated from `stage_dir`, sized
/// `size_mib`, then checked and shrunk to minimum. Rootless.
pub fn build(stage_dir: &Path, out_path: &Path, size_mib: u32) -> Result<Ext4Image, BuildError> {
    if !tools_available() {
        return Err(BuildError::MissingTool(
            "e2fsprogs (mke2fs/e2fsck/resize2fs)".into(),
        ));
    }
    // Fresh image file — remove any stale one so mke2fs doesn't prompt.
    let _ = std::fs::remove_file(out_path);

    // mke2fs -t ext4 -d <dir> -F <img> <size>M
    //   -d populates from the directory (no mount)
    //   -F forces creation on a plain file
    //   -L "" no label; -O ^has_journal keeps small images lean & Firecracker-friendly
    let mut mke2fs = tool_cmd("mke2fs")?;
    mke2fs
        .arg("-t")
        .arg("ext4")
        .arg("-d")
        .arg(stage_dir)
        .arg("-F")
        .arg("-q")
        .arg(out_path)
        .arg(format!("{size_mib}M"));
    run(mke2fs, "mke2fs")?;

    // e2fsck -fy: force check, answer yes. e2fsck exits 1 when it *fixed*
    // errors, which is success for us; treat only >=4 as failure.
    fsck(out_path)?;

    // resize2fs -M: shrink to the minimum size the content needs.
    let mut resize = tool_cmd("resize2fs")?;
    resize.arg("-M").arg(out_path);
    run(resize, "resize2fs")?;

    // A second fsck after the resize, to be safe.
    fsck(out_path)?;

    let size_bytes = std::fs::metadata(out_path)
        .map_err(|e| BuildError::Ext4(format!("stat image: {e}")))?
        .len();
    Ok(Ext4Image { size_bytes })
}

/// `e2fsck -fy`, accepting exit code 1 ("errors corrected") as success.
fn fsck(img: &Path) -> Result<(), BuildError> {
    let out = tool_cmd("e2fsck")?
        .arg("-f")
        .arg("-y")
        .arg(img)
        .output()
        .map_err(|e| BuildError::Ext4(format!("e2fsck: spawn: {e}")))?;
    // e2fsck exit codes are a bitmask: 0 clean, 1 errors corrected, 2 corrected
    // + reboot advised. 4+ means uncorrected errors / operational failure.
    let code = out.status.code().unwrap_or(-1);
    if !(0..4).contains(&code) {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(BuildError::Ext4(format!(
            "e2fsck exit {code}: {}",
            stderr.trim()
        )));
    }
    Ok(())
}

/// List the entries at `path` inside the image using `debugfs`. Used to verify a
/// built image without mounting it (returns the raw `ls -l` output). Requires
/// `debugfs` (part of e2fsprogs); returns an error if absent.
pub fn debugfs_ls(img: &Path, path: &str) -> Result<String, BuildError> {
    let out = tool_cmd("debugfs")?
        .arg("-R")
        .arg(format!("ls -l {path}"))
        .arg(img)
        .output()
        .map_err(|e| BuildError::Ext4(format!("debugfs: spawn: {e}")))?;
    if !out.status.success() {
        return Err(BuildError::Ext4(format!(
            "debugfs ls {path}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_stage(root: &Path) {
        std::fs::create_dir_all(root.join("app")).unwrap();
        std::fs::write(root.join("app/server.js"), b"console.log(1)").unwrap();
        std::fs::create_dir_all(root.join("sbin")).unwrap();
        std::fs::write(root.join("sbin/tenzro-initagent"), b"\x7fELF").unwrap();
        std::fs::create_dir_all(root.join("etc/tenzro")).unwrap();
        std::fs::write(
            root.join("etc/tenzro/run.json"),
            br#"{"cmd":["node","server.js"],"cwd":"/app","port":8080}"#,
        )
        .unwrap();
    }

    #[test]
    fn builds_and_verifies_real_ext4() {
        // Gate: skip cleanly if e2fsprogs is absent or the operator opts out.
        if std::env::var_os("TENZRO_SKIP_EXT4_TESTS").is_some() {
            eprintln!("skipping ext4 test (TENZRO_SKIP_EXT4_TESTS set)");
            return;
        }
        if !tools_available() {
            eprintln!("skipping ext4 test (e2fsprogs not installed)");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let stage_dir = tmp.path().join("stage");
        make_stage(&stage_dir);
        let img = tmp.path().join("rootfs.ext4");

        let built = build(&stage_dir, &img, 64).unwrap();
        assert!(built.size_bytes > 0);
        assert!(img.is_file());

        // Verify contents via debugfs (no mount).
        if which("debugfs").is_some() {
            let root_ls = debugfs_ls(&img, "/").unwrap();
            assert!(root_ls.contains("app"), "root has app dir: {root_ls}");
            assert!(root_ls.contains("sbin"), "root has sbin: {root_ls}");
            assert!(root_ls.contains("etc"), "root has etc: {root_ls}");

            let sbin_ls = debugfs_ls(&img, "/sbin").unwrap();
            assert!(
                sbin_ls.contains("tenzro-initagent"),
                "init present: {sbin_ls}"
            );
            let etc_ls = debugfs_ls(&img, "/etc/tenzro").unwrap();
            assert!(etc_ls.contains("run.json"), "run.json present: {etc_ls}");
        }
    }

    #[test]
    fn missing_stage_is_error_not_panic() {
        if !tools_available() {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let img = tmp.path().join("x.ext4");
        // mke2fs -d on a nonexistent dir must error.
        let r = build(&tmp.path().join("nope"), &img, 64);
        assert!(r.is_err());
    }
}
