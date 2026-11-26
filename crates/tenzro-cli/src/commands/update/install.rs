//! Swapping binaries on disk, and swapping them back.
//!
//! Two install layouts are supported, because there are two ways Tenzro gets
//! onto a machine:
//!
//! - **Versioned** (what `scripts/install/install.sh` and `install.ps1` make):
//!   `<root>/versions/<release>/bin/…` and a `current` pointer to the running
//!   release. An update builds the new release directory beside the old one
//!   (unchanged files hard-linked), then repoints `current` atomically and
//!   points `previous` at the old release. Only the new and the previous
//!   release directories are kept, as the installer does.
//! - **Flat** (a package or a copied binary): `<dir>/tenzro`, `<dir>/tenzro-node`.
//!   The old file stays beside the new one as `<name>.prev`.
//!
//! The pointers are symbolic links on Unix, switched by renaming a new link
//! over the old one, and directory junctions on Windows, switched by
//! rewriting the junction's reparse data in place (module `junction`). Both
//! are a single file-system operation: a path through `current` resolves to
//! the old release or to the new one, never to neither.
//!
//! An install is resumable: a run that stopped after building the release
//! directory, or after the switch, is completed by the next run with the same
//! verified files instead of being refused.
//!
//! Every release directory holds a `RELEASE` file naming its version
//! (`major.minor.patch`), written by the installers and by `tenzro update`,
//! so the installed release is known without running it
//! ([`installed_release`]).
//!
//! Rollback repoints `current` (or renames `<name>.prev` back) and runs no
//! Tenzro binary and reads no manifest: it works when the new binary will not
//! start. `apply` also writes a script that does the same without the new
//! `tenzro` ([`rollback_script`], [`rollback_cmd`]).
//!
//! A flat install is not updated in place on Windows: a running `.exe` cannot
//! be replaced there, and the flat Windows install is the MSI, which owns its
//! files ([`require_in_place_update`]).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use tenzro_onboarding_types::update_state;

use super::manifest::{ALLOWED_NAMES, Version};

/// The file in a release directory that names its version.
pub const RELEASE_FILE: &str = "RELEASE";

/// The file in a release directory that names its build kind (`cpu`, `cuda`,
/// `vulkan`, `edge`, ...). `tenzro update` writes it; a directory made by
/// `install.sh` or `install.ps1` carries the kind in its name instead.
pub const BUILD_FILE: &str = "BUILD";

fn valid_kind(kind: &str) -> bool {
    !kind.is_empty()
        && kind.len() <= 32
        && kind
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The build kind in the name of a release directory the installers make:
/// `tenzro-node-<os>-<arch>-<kind>-<first 12 hex digits of the archive's SHA-256>`.
fn kind_in_name(dir: &str) -> Option<&str> {
    let (rest, digest) = dir.strip_prefix("tenzro-node-")?.rsplit_once('-')?;
    if digest.len() != 12 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let rest = ["linux-", "macos-", "windows-"]
        .iter()
        .find_map(|os| rest.strip_prefix(os))?;
    let kind = ["x86_64-", "aarch64-"]
        .iter()
        .find_map(|arch| rest.strip_prefix(arch))?;
    valid_kind(kind).then_some(kind)
}

/// Refuses an update this layout cannot take on `os` (`std::env::consts::OS`).
pub fn require_in_place_update(os: &str, layout: &Layout) -> Result<()> {
    if os == "windows" && matches!(layout, Layout::Flat { .. }) {
        bail!(
            "`tenzro update` does not replace the files of an MSI install on Windows; install the new release with its MSI, or install with install.ps1, which `tenzro update` updates"
        );
    }
    Ok(())
}

/// The file name of binary `name` on this system (`tenzro-node.exe` on Windows).
pub fn file_name(name: &str) -> String {
    format!("{name}{}", std::env::consts::EXE_SUFFIX)
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

    /// Where the running copy of binary `name` (`tenzro`, `tenzro-node`) is.
    pub fn binary(&self, name: &str) -> PathBuf {
        match self {
            Layout::Versioned { root } => root.join("current").join("bin").join(file_name(name)),
            Layout::Flat { dir } => dir.join(file_name(name)),
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

    /// The release `current` points at, for a versioned install.
    pub fn current_release(&self) -> Option<String> {
        match self {
            Layout::Versioned { root } => link_name(&root.join("current")),
            Layout::Flat { .. } => None,
        }
    }

    /// The build kind of the current release of a versioned install: its
    /// `BUILD` file, else the kind in the directory name the installers gave
    /// it. A flat install records none.
    pub fn build_kind(&self) -> Option<String> {
        let Layout::Versioned { root } = self else {
            return None;
        };
        let current = link_name(&root.join("current"))?;
        std::fs::read_to_string(root.join("versions").join(&current).join(BUILD_FILE))
            .ok()
            .map(|k| k.trim().to_string())
            .filter(|k| valid_kind(k))
            .or_else(|| kind_in_name(&current).map(str::to_string))
    }
}

/// The library files of a new release, verified and staged: each
/// (`lib/<file>` or `bin/<file>`, staged path), and the links among them
/// (`lib/<file>`, the `lib/<file>` it points at).
#[derive(Debug, Default)]
pub struct StagedLibraries {
    pub files: Vec<(String, PathBuf)>,
    pub links: Vec<(String, String)>,
}

/// Whether the current release of a versioned install keeps files beside its
/// two binaries: a `lib/` folder, other files in `bin/` (the libraries
/// Windows loads from there) or the web console in `share/console/`. Such an
/// install takes its new release's from the libraries document; one without
/// them never reads it.
pub fn has_libraries(layout: &Layout) -> bool {
    let Layout::Versioned { root } = layout else {
        return false;
    };
    let Some(current) = link_name(&root.join("current")) else {
        return false;
    };
    let release = root.join("versions").join(current);
    release.join("lib").is_dir()
        || release.join("share").join("console").is_dir()
        || !extra_bin_files(&release.join("bin")).is_empty()
}

/// The files in `bin` other than the two binaries.
fn extra_bin_files(bin: &Path) -> Vec<String> {
    let binaries: Vec<String> = ALLOWED_NAMES.iter().map(|n| file_name(n)).collect();
    std::fs::read_dir(bin)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().to_str().map(str::to_string))
        .filter(|n| !binaries.contains(n))
        .collect()
}

/// What an install did.
#[derive(Debug, PartialEq, Eq)]
pub struct Installed {
    pub names: Vec<String>,
    /// Where the old binaries are kept.
    pub previous: String,
    /// The release kept as the fallback, for a versioned install.
    pub previous_release: Option<String>,
}

/// The release installed in `layout`, which a new release must not be older than.
///
/// For a versioned install it is the `RELEASE` file of the release `current`
/// names. A release directory without one, and a flat install, carry no
/// version on disk: the running `tenzro` (`running`, at `exe`) stands for
/// them only when it is the installed binary itself. Otherwise the installed
/// release cannot be told and the update is refused.
pub fn installed_release(layout: &Layout, running: Version, exe: &Path) -> Result<Version> {
    let runs_from = |dir: &Path| {
        matches!(
            (exe.canonicalize(), dir.canonicalize()),
            (Ok(e), Ok(d)) if e.parent() == Some(d.as_path())
        )
    };
    match layout {
        Layout::Versioned { root } => {
            let name = layout.current_release().ok_or_else(|| {
                anyhow!(
                    "{} is not a link to a release",
                    root.join("current").display()
                )
            })?;
            let release_dir = root.join("versions").join(&name);
            let file = release_dir.join(RELEASE_FILE);
            match std::fs::read_to_string(&file) {
                Ok(text) => text.trim().parse().map_err(|e: String| {
                    anyhow!("{} does not name a release: {e}", file.display())
                }),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    if runs_from(&release_dir.join("bin")) {
                        Ok(running)
                    } else {
                        bail!(
                            "the installed release {name} has no {RELEASE_FILE} file at {}, so its version is not known; install it again with install.sh or install.ps1, or run the update with its own tenzro",
                            file.display()
                        )
                    }
                }
                Err(e) => Err(e).with_context(|| format!("read {}", file.display())),
            }
        }
        Layout::Flat { dir } => {
            if runs_from(dir) {
                Ok(running)
            } else {
                bail!(
                    "the release of the binaries in {} is not recorded there; run the update with the tenzro in that folder",
                    dir.display()
                )
            }
        }
    }
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

/// Makes the entries of `dir` durable: a rename inside it survives a power loss.
#[cfg(unix)]
fn sync_dir(dir: &Path) -> Result<()> {
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .with_context(|| format!("sync {}", dir.display()))
}

/// NTFS journals the metadata of a rename and of a reparse-point change
/// itself, and a directory cannot be opened for a flush through std.
#[cfg(not(unix))]
fn sync_dir(_: &Path) -> Result<()> {
    Ok(())
}

/// Points `link` at `target` (`versions/<release>`, relative to the link's
/// directory) in one file-system operation, and makes it durable.
#[cfg(unix)]
fn point(link: &Path, target: &str) -> Result<()> {
    let tmp = link.with_extension("update-tmp");
    let _ = std::fs::remove_file(&tmp);
    std::os::unix::fs::symlink(target, &tmp).with_context(|| format!("link {}", tmp.display()))?;
    std::fs::rename(&tmp, link).with_context(|| format!("repoint {}", link.display()))?;
    sync_dir(link.parent().unwrap_or(Path::new(".")))
}

/// Points the junction `link` at `target` (`versions/<release>`, relative to
/// the link's directory). An existing junction is retargeted in place; see
/// module `junction` for why that is the atomic switch on NTFS.
#[cfg(windows)]
fn point(link: &Path, target: &str) -> Result<()> {
    let dir = link.parent().unwrap_or(Path::new("."));
    let abs = std::path::absolute(dir.join(target.replace('/', "\\")))
        .with_context(|| format!("resolve {target}"))?;
    junction::point(link, &abs)
}

#[cfg(not(any(unix, windows)))]
fn point(_: &Path, _: &str) -> Result<()> {
    bail!("`tenzro update` has no release pointer on this platform")
}

/// Removes the pointer `link` (a symbolic link, or a junction on Windows), not what it points at.
fn unlink(link: &Path) -> std::io::Result<()> {
    if cfg!(windows) {
        std::fs::remove_dir(link)
    } else {
        std::fs::remove_file(link)
    }
}

fn copy_into(src: &Path, dst: &Path) -> Result<()> {
    copy_file(src, dst)?;
    set_exec(dst)
}

/// Copies `src` to `dst` and syncs it, keeping the destination's mode as a plain file.
fn copy_file(src: &Path, dst: &Path) -> Result<()> {
    std::fs::copy(src, dst)
        .with_context(|| format!("copy {} to {}", src.display(), dst.display()))?;
    // Opened for writing: on Windows FlushFileBuffers needs write access, and
    // `sync_all` on a handle opened read-only fails with "Access is denied".
    std::fs::OpenOptions::new()
        .write(true)
        .open(dst)
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

/// Copies the tree `src` to `dst` with files hard-linked, leaving out the
/// paths in `skip` (relative to `src`). A file that is about to be replaced is
/// never linked: on Windows the link of a running program could not be removed.
fn clone_tree(src: &Path, dst: &Path, skip: &[PathBuf]) -> Result<()> {
    fn walk(src: &Path, dst: &Path, rel: &Path, skip: &[PathBuf]) -> Result<()> {
        std::fs::create_dir(dst).with_context(|| format!("create {}", dst.display()))?;
        for entry in std::fs::read_dir(src).with_context(|| format!("read {}", src.display()))? {
            let entry = entry?;
            let rel = rel.join(entry.file_name());
            if skip.contains(&rel) {
                continue;
            }
            let (from, to) = (entry.path(), dst.join(entry.file_name()));
            let kind = entry.file_type()?;
            if kind.is_dir() {
                walk(&from, &to, &rel, skip)?;
            } else if kind.is_symlink() {
                #[cfg(unix)]
                std::os::unix::fs::symlink(std::fs::read_link(&from)?, &to)?;
            } else {
                link_or_copy(&from, &to)?;
            }
        }
        Ok(())
    }
    walk(src, dst, Path::new(""), skip)
}

fn link_name(link: &Path) -> Option<String> {
    std::fs::read_link(link)
        .ok()?
        .file_name()?
        .to_str()
        .map(str::to_string)
}

/// Whether `installed` holds exactly the bytes of `staged`.
fn same_bytes(installed: &Path, staged: &Path) -> bool {
    matches!(
        (update_state::file_sha256(installed), update_state::file_sha256(staged)),
        (Ok(a), Ok(b)) if a == b
    )
}

/// Installs the verified files in `staged` (`name`, path) and keeps what they replace.
///
/// Run again with the same files after an interruption, it finishes the
/// install: a release directory left half-built, or built and not yet made
/// current, is rebuilt from the verified files; a release already made
/// current is accepted when its binaries are the verified files.
///
/// A versioned install records `build` as the new release's kind and runs
/// `check` on the new `tenzro-node` where it will run from, before `current`
/// is switched: an error from it leaves the install as it was. With
/// `libraries`, the new release's `lib/`, `share/console/` and the files
/// beside the binaries in `bin/` are exactly those, and none of the old
/// release's are carried over.
pub fn install(
    layout: &Layout,
    release: &str,
    staged: &[(String, PathBuf)],
    build: Option<&str>,
    libraries: Option<&StagedLibraries>,
    check: &dyn Fn(&Path) -> Result<()>,
) -> Result<Installed> {
    if staged.is_empty() {
        bail!("nothing to install");
    }
    let names = staged.iter().map(|(n, _)| n.clone()).collect();
    match layout {
        Layout::Versioned { root } => {
            let versions = root.join("versions");
            let current = link_name(&root.join("current")).ok_or_else(|| {
                anyhow!(
                    "{} is not a link to a release",
                    root.join("current").display()
                )
            })?;
            let new_dir = versions.join(release);
            if current == release {
                // An earlier run switched `current` and stopped before it
                // recorded the install.
                for (name, src) in staged {
                    if !same_bytes(&new_dir.join("bin").join(file_name(name)), src) {
                        bail!(
                            "release {release} is already current at {} with a different {name} than the signed one; roll back first",
                            new_dir.display()
                        );
                    }
                }
                let previous = link_name(&root.join("previous"));
                return Ok(Installed {
                    names,
                    previous: previous.as_ref().map_or_else(
                        || "none".to_string(),
                        |p| versions.join(p).display().to_string(),
                    ),
                    previous_release: previous,
                });
            }
            if link_name(&root.join("previous")).as_deref() == Some(release) {
                bail!(
                    "release {release} is the previous release kept at {}; it is not rebuilt over the fallback",
                    new_dir.display()
                );
            }
            // A directory for this release that is not current was left by an
            // interrupted run or by a rollback away from it: it is rebuilt
            // from the files just verified.
            if new_dir.exists() {
                std::fs::remove_dir_all(&new_dir)
                    .with_context(|| format!("remove the stale {}", new_dir.display()))?;
            }
            let old = current;
            let tmp = versions.join(format!(".{release}.new"));
            let _ = std::fs::remove_dir_all(&tmp);
            // The digests of the verified files, by their path in the new
            // release, to hold the copies to after the check.
            let digests = staged
                .iter()
                .map(|(name, src)| (Path::new("bin").join(file_name(name)), src))
                .chain(
                    libraries
                        .iter()
                        .flat_map(|l| l.files.iter().map(|(name, src)| (PathBuf::from(name), src))),
                )
                .map(|(at, src)| {
                    update_state::file_sha256(src)
                        .map(|h| (at.clone(), h))
                        .with_context(|| format!("read the staged {}", at.display()))
                })
                .collect::<Result<Vec<_>>>()?;
            let built = (|| -> Result<()> {
                let old_extras = match libraries {
                    Some(_) => extra_bin_files(&versions.join(&old).join("bin")),
                    None => Vec::new(),
                };
                let replaced: Vec<PathBuf> = staged
                    .iter()
                    .map(|(n, _)| Path::new("bin").join(file_name(n)))
                    .chain(Some(PathBuf::from(RELEASE_FILE)))
                    .chain(build.map(|_| PathBuf::from(BUILD_FILE)))
                    .chain(libraries.map(|_| PathBuf::from("lib")))
                    .chain(libraries.map(|_| Path::new("share").join("console")))
                    .chain(old_extras.iter().map(|n| Path::new("bin").join(n)))
                    .collect();
                clone_tree(&versions.join(&old), &tmp, &replaced)?;
                for (name, src) in staged {
                    copy_into(src, &tmp.join("bin").join(file_name(name)))?;
                }
                if let Some(libraries) = libraries {
                    std::fs::create_dir_all(tmp.join("lib"))
                        .with_context(|| format!("create {}", tmp.join("lib").display()))?;
                    for (name, src) in &libraries.files {
                        let at = tmp.join(name);
                        if let Some(dir) = at.parent() {
                            std::fs::create_dir_all(dir)
                                .with_context(|| format!("create {}", dir.display()))?;
                        }
                        // Programs and libraries are executable; the console's pages are not.
                        if name.starts_with("share/") {
                            copy_file(src, &at)?;
                        } else {
                            copy_into(src, &at)?;
                        }
                    }
                    for (name, target) in &libraries.links {
                        let at = tmp.join(name);
                        let to = Path::new(target)
                            .file_name()
                            .ok_or_else(|| anyhow!("link {name} names no file"))?;
                        #[cfg(unix)]
                        std::os::unix::fs::symlink(to, &at)
                            .with_context(|| format!("link {}", at.display()))?;
                        #[cfg(not(unix))]
                        copy_into(&tmp.join("lib").join(to), &at)?;
                    }
                }
                std::fs::write(tmp.join(RELEASE_FILE), format!("{release}\n"))
                    .with_context(|| format!("write {}", tmp.join(RELEASE_FILE).display()))?;
                if let Some(kind) = build {
                    std::fs::write(tmp.join(BUILD_FILE), format!("{kind}\n"))
                        .with_context(|| format!("write {}", tmp.join(BUILD_FILE).display()))?;
                }
                check(&tmp.join("bin").join(file_name("tenzro-node")))?;
                // What is made current is what was verified: a copy changed
                // between the copy and here is refused.
                for (at, want) in &digests {
                    if update_state::file_sha256(&tmp.join(at)).ok().as_deref()
                        != Some(want.as_str())
                    {
                        bail!(
                            "the {} written to the new release is not the verified one; nothing was changed",
                            at.display()
                        );
                    }
                }
                #[cfg(unix)]
                for (name, target) in libraries.iter().flat_map(|l| l.links.iter()) {
                    let to = Path::new(target).file_name().map(Path::new);
                    if std::fs::read_link(tmp.join(name)).ok().as_deref() != to {
                        bail!(
                            "the link {name} in the new release does not point at {target}; nothing was changed"
                        );
                    }
                }
                std::fs::rename(&tmp, &new_dir)
                    .with_context(|| format!("create {}", new_dir.display()))?;
                sync_dir(&versions)
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
                previous_release: Some(old),
            })
        }
        Layout::Flat { dir } => {
            if libraries.is_some() {
                bail!("a flat install keeps no libraries beside its binaries");
            }
            let target = |n: &str| dir.join(file_name(n));
            let fresh = |n: &str| dir.join(format!(".{}.update-new", file_name(n)));
            let prev = |n: &str| dir.join(format!("{}.prev", file_name(n)));
            // A file already holding the verified bytes was renamed into place
            // by an interrupted run; its `.prev` is the real previous binary
            // and is kept as it is.
            let todo: Vec<&(String, PathBuf)> = staged
                .iter()
                .filter(|(n, src)| !same_bytes(&target(n), src))
                .collect();
            let cleanup = || {
                todo.iter()
                    .for_each(|(n, _)| drop(std::fs::remove_file(fresh(n))))
            };
            let prepared = (|| -> Result<()> {
                for (name, src) in &todo {
                    copy_into(src, &fresh(name))?;
                }
                for (name, _) in &todo {
                    let _ = std::fs::remove_file(prev(name));
                    link_or_copy(&target(name), &prev(name))?;
                }
                Ok(())
            })();
            if let Err(e) = prepared {
                cleanup();
                return Err(e);
            }
            let mut done: Vec<&str> = Vec::new();
            for (name, _) in &todo {
                if let Err(e) = std::fs::rename(fresh(name), target(name)) {
                    for n in done {
                        let _ = std::fs::rename(prev(n), target(n));
                    }
                    cleanup();
                    return Err(anyhow!("install {name}: {e}"));
                }
                done.push(name);
            }
            sync_dir(dir)?;
            Ok(Installed {
                names,
                previous: format!("{}/<name>.prev", dir.display()),
                previous_release: None,
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
            let _ = unlink(&prev_link);
            Ok(RolledBack {
                restored: vec![prev],
            })
        }
        Layout::Flat { dir } => {
            let prev = |n: &str| dir.join(format!("{}.prev", file_name(n)));
            let have: Vec<&str> = ALLOWED_NAMES
                .into_iter()
                .filter(|n| prev(n).is_file())
                .collect();
            if have.is_empty() {
                bail!(
                    "there is no previous binary to restore in {}",
                    dir.display()
                );
            }
            for n in &have {
                std::fs::rename(prev(n), dir.join(file_name(n)))
                    .with_context(|| format!("restore {n}"))?;
            }
            sync_dir(dir)?;
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

/// A `cmd` script for a versioned Windows install, for when the new
/// `tenzro.exe` will not start. It runs the previous release's own
/// `tenzro.exe`, which repoints `current` at itself and closes the trial in
/// `data_dir`. `cmd` has no way to read a junction's target, so the script
/// does not repoint it by hand.
pub fn rollback_cmd(root: &Path, data_dir: &Path) -> String {
    let q = |p: &Path| p.display().to_string().replace('"', "");
    format!(
        "@echo off\r\nrem Written by `tenzro update apply`. Restores the previous Tenzro release with that release's own tenzro.exe.\r\nif not exist \"{root}\\previous\\bin\\tenzro.exe\" (echo no previous release to restore 1>&2 & exit /b 1)\r\n\"{root}\\previous\\bin\\tenzro.exe\" update rollback --install-dir \"{root}\" --data-dir \"{data}\"\r\n",
        root = q(root),
        data = q(data_dir),
    )
}

/// Directory junctions (NTFS mount points), the release pointers on Windows.
///
/// A junction needs no privilege to create, unlike a symbolic link, and is
/// what `install.ps1` makes. It cannot be replaced by a rename (NTFS will not
/// rename over a directory), and removing it and creating it again leaves a
/// moment with no `current`. Instead an existing junction is retargeted with
/// `FSCTL_SET_REPARSE_POINT`: that replaces the reparse data of the one
/// directory entry in a single file-system call, which NTFS applies under the
/// file's lock and records in its metadata journal, so every open through the
/// junction sees either the old target or the new one, also after a crash.
/// Pure parts (the reparse buffer) are built on every platform so they are tested.
pub mod junction {
    use anyhow::{Result, bail};

    /// `IO_REPARSE_TAG_MOUNT_POINT`.
    pub const MOUNT_POINT_TAG: u32 = 0xA000_0003;
    /// `MAXIMUM_REPARSE_DATA_BUFFER_SIZE`.
    pub const MAX_REPARSE_BYTES: usize = 16 * 1024;

    /// The NT name and the display name of an absolute local path:
    /// `C:\a\b` (or `\\?\C:\a\b`) gives `\??\C:\a\b` and `C:\a\b`. A junction
    /// can only point at a local volume, so a UNC or relative path is refused.
    pub fn target_names(target: &str) -> Result<(String, String)> {
        let plain = target.strip_prefix(r"\\?\").unwrap_or(target);
        let b = plain.as_bytes();
        let drive = b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\';
        if !drive || plain.contains('/') {
            bail!("a junction needs an absolute local path like C:\\dir, not {target:?}");
        }
        let plain = plain.trim_end_matches('\\');
        let plain = if plain.len() == 2 {
            format!("{plain}\\")
        } else {
            plain.to_string()
        };
        Ok((format!(r"\??\{plain}"), plain))
    }

    /// The `REPARSE_DATA_BUFFER` of a mount point to `target`.
    pub fn reparse_data(target: &str) -> Result<Vec<u8>> {
        let (nt, print) = target_names(target)?;
        let nt: Vec<u16> = nt.encode_utf16().collect();
        let print: Vec<u16> = print.encode_utf16().collect();
        let (nt_bytes, print_bytes) = (nt.len() * 2, print.len() * 2);
        // Four u16 name fields, then both names, each followed by a NUL.
        let data_len = 8 + nt_bytes + 2 + print_bytes + 2;
        if 8 + data_len > MAX_REPARSE_BYTES {
            bail!("the junction target is too long: {target}");
        }
        let u16le = |v: usize| (v as u16).to_le_bytes();
        let mut out = Vec::with_capacity(8 + data_len);
        out.extend_from_slice(&MOUNT_POINT_TAG.to_le_bytes());
        out.extend_from_slice(&u16le(data_len));
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&u16le(0));
        out.extend_from_slice(&u16le(nt_bytes));
        out.extend_from_slice(&u16le(nt_bytes + 2));
        out.extend_from_slice(&u16le(print_bytes));
        for c in nt.iter().chain(&[0]).chain(&print).chain(&[0]) {
            out.extend_from_slice(&c.to_le_bytes());
        }
        Ok(out)
    }

    /// Points the junction `link` at the directory `target`: retargets it in
    /// place when it exists, creates it otherwise.
    #[cfg(windows)]
    pub fn point(link: &std::path::Path, target: &std::path::Path) -> Result<()> {
        use anyhow::Context;
        if !target.is_dir() {
            bail!("{} is not a directory", target.display());
        }
        let data = reparse_data(&target.display().to_string())?;
        match std::fs::symlink_metadata(link) {
            Ok(m) if m.file_type().is_symlink() => set_reparse_point(link, &data)
                .with_context(|| format!("repoint {}", link.display())),
            Ok(_) => bail!(
                "{} is a real directory or file, not a junction",
                link.display()
            ),
            Err(_) => {
                std::fs::create_dir(link).with_context(|| format!("create {}", link.display()))?;
                set_reparse_point(link, &data).map_err(|e| {
                    let _ = std::fs::remove_dir(link);
                    anyhow::anyhow!("make {} a junction: {e}", link.display())
                })
            }
        }
    }

    /// Writes `data` as the reparse point of the directory `dir`. On a
    /// junction that exists this replaces its target.
    #[cfg(windows)]
    fn set_reparse_point(dir: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_WRITE, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
        };
        use windows_sys::Win32::System::IO::DeviceIoControl;
        use windows_sys::Win32::System::Ioctl::FSCTL_SET_REPARSE_POINT;

        let wide: Vec<u16> = dir.as_os_str().encode_wide().chain(Some(0)).collect();
        // SAFETY: `wide` is a NUL-terminated UTF-16 path that outlives the
        // call; the other arguments are flags and null optional pointers.
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error());
        }
        let mut returned = 0u32;
        // SAFETY: `handle` is open; `data` is a complete reparse buffer of
        // the stated length; no output buffer and no overlapped I/O.
        let ok = unsafe {
            DeviceIoControl(
                handle,
                FSCTL_SET_REPARSE_POINT,
                data.as_ptr().cast(),
                data.len() as u32,
                std::ptr::null_mut(),
                0,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        let err = std::io::Error::last_os_error();
        // SAFETY: `handle` came from CreateFileW and is closed once.
        unsafe { CloseHandle(handle) };
        if ok == 0 { Err(err) } else { Ok(()) }
    }
}
