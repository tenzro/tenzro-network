//! Swapping binaries on disk, and swapping them back.
//!
//! Two install layouts are supported, because there are two ways Tenzro gets
//! onto a machine:
//!
//! - **Versioned** (what `scripts/install/install.sh` makes): `<root>/versions/<release>/bin/…`,
//!   a `current` symlink to the running release. An update builds the new
//!   release directory beside the old one (unchanged files hard-linked), then
//!   repoints `current` atomically and points `previous` at the old release.
//!   Only the new and the previous release directories are kept, as the
//!   installer does.
//! - **Flat** (a package or a copied binary): `<dir>/tenzro`, `<dir>/tenzro-node`.
//!   The old file stays beside the new one as `<name>.prev`.
//!
//! Rollback is a rename or a symlink swap and runs no Tenzro binary and reads
//! no manifest: it works when the new binary will not start. `apply` also
//! writes `rollback.sh`, which does the same with only `sh`.
//!
//! Unix only: a running `.exe` cannot be replaced in place on Windows, where a
//! new release is installed with its MSI ([`require_in_place_update`]).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};

use super::manifest::ALLOWED_NAMES;

/// Refuses `os` (`std::env::consts::OS`) where binaries cannot be swapped on disk.
pub fn require_in_place_update(os: &str) -> Result<()> {
    if os == "windows" {
        bail!(
            "`tenzro update` does not replace a running program on Windows; install the new release with its MSI"
        );
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Layout {
    Versioned { root: PathBuf },
    Flat { dir: PathBuf },
}

impl Layout {
    /// A directory holding `versions/` and a `current` link is a versioned install.
    pub fn detect(dir: &Path) -> Layout {
        if dir.join("versions").is_dir() && dir.join("current").is_symlink() {
            Layout::Versioned {
                root: dir.to_path_buf(),
            }
        } else {
            Layout::Flat {
                dir: dir.to_path_buf(),
            }
        }
    }

    /// The layout of the binary at `exe`: `<root>/versions/<v>/bin/<name>` is versioned.
    pub fn of_executable(exe: &Path) -> Result<Layout> {
        let exe = exe
            .canonicalize()
            .with_context(|| format!("resolve {}", exe.display()))?;
        let bin = exe
            .parent()
            .ok_or_else(|| anyhow!("{} has no directory", exe.display()))?;
        let versioned_root = bin
            .parent()
            .and_then(Path::parent)
            .filter(|versions| versions.file_name().is_some_and(|n| n == "versions"))
            .and_then(Path::parent)
            .filter(|root| root.join("current").is_symlink());
        Ok(match versioned_root {
            Some(root) => Layout::Versioned {
                root: root.to_path_buf(),
            },
            None => Layout::Flat {
                dir: bin.to_path_buf(),
            },
        })
    }

    /// Where the running copy of `name` is.
    pub fn binary(&self, name: &str) -> PathBuf {
        match self {
            Layout::Versioned { root } => root.join("current").join("bin").join(name),
            Layout::Flat { dir } => dir.join(name),
        }
    }

    /// The directory an update changes: the install root, or the folder
    /// holding the binaries.
    pub fn dir(&self) -> &Path {
        match self {
            Layout::Versioned { root } => root,
            Layout::Flat { dir } => dir,
        }
    }

    /// The names of `ALLOWED_NAMES` this install has.
    pub fn installed_names(&self) -> Vec<&'static str> {
        ALLOWED_NAMES
            .into_iter()
            .filter(|n| self.binary(n).is_file())
            .collect()
    }
}

/// What an install did.
#[derive(Debug, PartialEq, Eq)]
pub struct Installed {
    pub names: Vec<String>,
    /// Where the old binaries are kept.
    pub previous: String,
}

#[cfg(unix)]
fn set_exec(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .with_context(|| format!("chmod {}", path.display()))
}

#[cfg(not(unix))]
fn set_exec(_: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn point(link: &Path, target: &str) -> Result<()> {
    let tmp = link.with_extension("update-tmp");
    let _ = std::fs::remove_file(&tmp);
    std::os::unix::fs::symlink(target, &tmp).with_context(|| format!("link {}", tmp.display()))?;
    std::fs::rename(&tmp, link).with_context(|| format!("repoint {}", link.display()))
}

#[cfg(not(unix))]
fn point(_: &Path, _: &str) -> Result<()> {
    bail!("`tenzro update` does not install on this platform yet")
}

fn copy_into(src: &Path, dst: &Path) -> Result<()> {
    std::fs::copy(src, dst)
        .with_context(|| format!("copy {} to {}", src.display(), dst.display()))?;
    set_exec(dst)?;
    std::fs::File::open(dst)
        .and_then(|f| f.sync_all())
        .with_context(|| format!("sync {}", dst.display()))
}

/// Links `from` at `to`, or copies it where the file system will not link.
fn link_or_copy(from: &Path, to: &Path) -> Result<()> {
    if std::fs::hard_link(from, to).is_err() {
        std::fs::copy(from, to).with_context(|| format!("copy {}", from.display()))?;
    }
    Ok(())
}

fn clone_tree(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir(dst).with_context(|| format!("create {}", dst.display()))?;
    for entry in std::fs::read_dir(src).with_context(|| format!("read {}", src.display()))? {
        let entry = entry?;
        let (from, to) = (entry.path(), dst.join(entry.file_name()));
        let kind = entry.file_type()?;
        if kind.is_dir() {
            clone_tree(&from, &to)?;
        } else if kind.is_symlink() {
            #[cfg(unix)]
            std::os::unix::fs::symlink(std::fs::read_link(&from)?, &to)?;
        } else {
            link_or_copy(&from, &to)?;
        }
    }
    Ok(())
}

fn link_name(link: &Path) -> Option<String> {
    std::fs::read_link(link)
        .ok()?
        .file_name()?
        .to_str()
        .map(str::to_string)
}

/// Installs the verified files in `staged` (`name`, path) and keeps what they replace.
pub fn install(layout: &Layout, release: &str, staged: &[(String, PathBuf)]) -> Result<Installed> {
    if staged.is_empty() {
        bail!("nothing to install");
    }
    let names = staged.iter().map(|(n, _)| n.clone()).collect();
    match layout {
        Layout::Versioned { root } => {
            let versions = root.join("versions");
            let old = link_name(&root.join("current")).ok_or_else(|| {
                anyhow!(
                    "{} is not a link to a release",
                    root.join("current").display()
                )
            })?;
            let new_dir = versions.join(release);
            if new_dir.exists() {
                bail!(
                    "release {release} is already installed at {}",
                    new_dir.display()
                );
            }
            let tmp = versions.join(format!(".{release}.new"));
            let _ = std::fs::remove_dir_all(&tmp);
            let built = (|| -> Result<()> {
                clone_tree(&versions.join(&old), &tmp)?;
                for (name, src) in staged {
                    let dst = tmp.join("bin").join(name);
                    let _ = std::fs::remove_file(&dst);
                    copy_into(src, &dst)?;
                }
                std::fs::rename(&tmp, &new_dir)
                    .with_context(|| format!("create {}", new_dir.display()))
            })();
            if let Err(e) = built {
                let _ = std::fs::remove_dir_all(&tmp);
                return Err(e);
            }
            point(&root.join("previous"), &format!("versions/{old}"))?;
            point(&root.join("current"), &format!("versions/{release}"))?;
            for entry in std::fs::read_dir(&versions)?.flatten() {
                let n = entry.file_name();
                if n != release && n != old.as_str() {
                    let _ = std::fs::remove_dir_all(entry.path());
                }
            }
            Ok(Installed {
                names,
                previous: versions.join(&old).display().to_string(),
            })
        }
        Layout::Flat { dir } => {
            let fresh = |n: &str| dir.join(format!(".{n}.update-new"));
            let prev = |n: &str| dir.join(format!("{n}.prev"));
            let cleanup = || {
                staged
                    .iter()
                    .for_each(|(n, _)| drop(std::fs::remove_file(fresh(n))))
            };
            let prepared = (|| -> Result<()> {
                for (name, src) in staged {
                    copy_into(src, &fresh(name))?;
                }
                for (name, _) in staged {
                    let _ = std::fs::remove_file(prev(name));
                    link_or_copy(&dir.join(name), &prev(name))?;
                }
                Ok(())
            })();
            if let Err(e) = prepared {
                cleanup();
                return Err(e);
            }
            let mut done: Vec<&str> = Vec::new();
            for (name, _) in staged {
                if let Err(e) = std::fs::rename(fresh(name), dir.join(name)) {
                    for n in done {
                        let _ = std::fs::rename(prev(n), dir.join(n));
                    }
                    cleanup();
                    return Err(anyhow!("install {name}: {e}"));
                }
                done.push(name);
            }
            Ok(Installed {
                names,
                previous: format!("{}/<name>.prev", dir.display()),
            })
        }
    }
}

/// What a rollback restored.
#[derive(Debug, PartialEq, Eq)]
pub struct RolledBack {
    pub restored: Vec<String>,
}

/// Puts the previous binaries back. Reads only the install directory.
pub fn rollback(layout: &Layout) -> Result<RolledBack> {
    match layout {
        Layout::Versioned { root } => {
            let prev_link = root.join("previous");
            let prev = link_name(&prev_link).ok_or_else(|| {
                anyhow!(
                    "there is no previous release to restore at {}",
                    root.display()
                )
            })?;
            if !root.join("versions").join(&prev).is_dir() {
                bail!(
                    "the previous release {prev} is no longer on disk at {}",
                    root.join("versions").display()
                );
            }
            point(&root.join("current"), &format!("versions/{prev}"))?;
            let _ = std::fs::remove_file(&prev_link);
            Ok(RolledBack {
                restored: vec![prev],
            })
        }
        Layout::Flat { dir } => {
            let have: Vec<&str> = ALLOWED_NAMES
                .into_iter()
                .filter(|n| dir.join(format!("{n}.prev")).is_file())
                .collect();
            if have.is_empty() {
                bail!(
                    "there is no previous binary to restore in {}",
                    dir.display()
                );
            }
            for n in &have {
                std::fs::rename(dir.join(format!("{n}.prev")), dir.join(n))
                    .with_context(|| format!("restore {n}"))?;
            }
            Ok(RolledBack {
                restored: have.iter().map(|s| s.to_string()).collect(),
            })
        }
    }
}

fn sh_quote(p: &Path) -> String {
    format!("'{}'", p.display().to_string().replace('\'', "'\\''"))
}

/// A POSIX `sh` script doing what [`rollback`] does, for when `tenzro` itself will not start.
pub fn rollback_script(layout: &Layout) -> String {
    let body = match layout {
        Layout::Versioned { root } => format!(
            "ROOT={}\n[ -L \"$ROOT/previous\" ] || {{ echo 'no previous release to restore' >&2; exit 1; }}\nln -sfn \"$(readlink \"$ROOT/previous\")\" \"$ROOT/current\"\nrm -f \"$ROOT/previous\"\n",
            sh_quote(root)
        ),
        Layout::Flat { dir } => format!(
            "DIR={}\nfound=0\nfor n in tenzro tenzro-node; do\n  if [ -f \"$DIR/$n.prev\" ]; then mv -f \"$DIR/$n.prev\" \"$DIR/$n\"; found=1; fi\ndone\n[ \"$found\" = 1 ] || {{ echo 'no previous binary to restore' >&2; exit 1; }}\n",
            sh_quote(dir)
        ),
    };
    format!(
        "#!/bin/sh\n# Written by `tenzro update apply`. Restores the previous Tenzro release; runs no Tenzro binary.\nset -eu\n{body}echo 'restored the previous release; restart the node when you choose'\n"
    )
}
