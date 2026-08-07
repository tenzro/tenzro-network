//! Sealing a machine's own key material to its TPM.
//!
//! # Why a machine must not keep its key in a file
//!
//! An autonomous machine — one no human delegated — answers for itself. What
//! makes that claim mean anything is that the key it answers with cannot be
//! copied off the machine. A key in a file is copyable by anything that can
//! read the file: a backup, a stolen disk, a container escape, a misapplied
//! `chmod`. Copy the file and you *are* the machine, and there is no human to
//! notice you are not.
//!
//! So a machine that stores its own key seals it to its TPM. The blob on disk
//! is ciphertext under the TPM's storage hierarchy: only that TPM can unseal
//! it, and it will not export the key that would let anything else try.
//!
//! # This is the same rule as the identity rule
//!
//! [`crate::hardware_identity`] admits a machine with no human controller only
//! when it holds an attestable root of trust. This module is the other half of
//! the same sentence: the anchor that lets a machine speak for itself is also
//! the thing that must hold the key it speaks with. A machine with a TPM good
//! enough to anchor its identity is by construction a machine with a TPM good
//! enough to seal its key — and a machine without one was never allowed to be
//! autonomous, so it never reaches this path.
//!
//! # Why the TPM tools rather than a linked TSS
//!
//! `tpm2-tools` is how this workspace already talks to vendor hardware —
//! `nvidia-smi`, `rocm-smi`, `ffmpeg` are all driven the same way. Linking
//! `tss2-esys` would put a native build dependency under a crate that has to
//! compile on hosts with no TPM at all, which would mean feature-gating it off
//! by default and shipping a sealing path nobody exercises.
//!
//! The plaintext never crosses the process boundary in a file: it is written to
//! the tool's stdin, and the tool writes back only the sealed public and private
//! blobs.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use zeroize::Zeroizing;

use crate::error::{Result, TeeError};

/// Filenames of the two halves of a sealed object, inside its directory.
const SEALED_PUB: &str = "sealed.pub";
const SEALED_PRIV: &str = "sealed.priv";
/// Persistent handle the sealing parent is created at.
///
/// A fixed handle rather than a context file so the parent survives reboots and
/// every process finds the same one. `0x81010001` is inside the TCG-reserved
/// owner-hierarchy persistent range for application keys.
const PARENT_HANDLE: &str = "0x81010001";

/// Whether this host has a TPM this module can drive.
///
/// Checks both the resource-manager device and the tooling, because either
/// missing makes sealing impossible: `/dev/tpmrm0` is the multiplexed device
/// every non-exclusive user should talk to, and the tools are how we talk.
pub fn tpm_available() -> bool {
    (Path::new("/dev/tpmrm0").exists() || Path::new("/dev/tpm0").exists())
        && which_tool("tpm2_create").is_some()
        && which_tool("tpm2_createprimary").is_some()
        && which_tool("tpm2_unseal").is_some()
        && which_tool("tpm2_load").is_some()
}

/// Resolve a tool on `PATH`, returning its path.
fn which_tool(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join(name))
            .find(|candidate| candidate.is_file())
    })
}

/// Run a TPM tool, mapping a non-zero exit into a typed error carrying stderr.
fn run(tool: &str, args: &[&str], stdin: Option<&[u8]>) -> Result<Vec<u8>> {
    let mut child = Command::new(tool)
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| TeeError::not_available(format!("{tool} could not be started: {e}")))?;

    if let Some(bytes) = stdin {
        child
            .stdin
            .as_mut()
            .ok_or_else(|| TeeError::not_available("stdin was not piped"))?
            .write_all(bytes)
            .map_err(|e| TeeError::not_available(format!("writing to {tool}: {e}")))?;
    }

    let out = child
        .wait_with_output()
        .map_err(|e| TeeError::not_available(format!("{tool} did not complete: {e}")))?;
    if !out.status.success() {
        return Err(TeeError::not_available(format!(
            "{tool} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(out.stdout)
}

/// Ensure the sealing parent exists at [`PARENT_HANDLE`].
///
/// Idempotent: creating it when it is already there fails, and that failure is
/// the success case on every boot after the first. Distinguished from a real
/// error by re-probing the handle rather than by matching on the message, which
/// would break the first time the tools reworded it.
fn ensure_parent() -> Result<()> {
    if parent_exists() {
        return Ok(());
    }
    // A primary in the owner hierarchy is deterministically re-derivable from
    // the TPM's own seed, so this reconstructs the *same* parent after a
    // clear-and-recreate — the sealed blobs stay unsealable by anything else.
    let ctx = tempfile::Builder::new()
        .prefix("tenzro-tpm-parent")
        .tempfile()
        .map_err(|e| TeeError::not_available(format!("temp file: {e}")))?;
    let ctx_path = ctx.path().to_string_lossy().into_owned();

    run(
        "tpm2_createprimary",
        &["-C", "o", "-g", "sha256", "-G", "ecc", "-c", &ctx_path],
        None,
    )?;
    run(
        "tpm2_evictcontrol",
        &["-C", "o", "-c", &ctx_path, PARENT_HANDLE],
        None,
    )?;

    if !parent_exists() {
        return Err(TeeError::not_available(
            "sealing parent could not be made persistent",
        ));
    }
    Ok(())
}

/// Whether the persistent sealing parent is present.
fn parent_exists() -> bool {
    run("tpm2_readpublic", &["-c", PARENT_HANDLE], None).is_ok()
}

/// Seal `secret` to this TPM, writing the sealed object into `dir`.
///
/// The secret reaches the TPM over the tool's stdin and is never written to
/// disk in plaintext. What lands in `dir` is the public and private halves of a
/// TPM object whose sensitive data only this TPM can recover.
///
/// # Errors
///
/// [`TeeError::NotAvailable`] when the host has no usable TPM, or when the TPM
/// refuses. Sealing never degrades to writing the plaintext — a machine that
/// cannot seal must not pretend it did, because the whole value of the
/// autonomous claim rests on the key being unextractable.
pub fn seal(dir: &Path, secret: &[u8]) -> Result<()> {
    if !tpm_available() {
        return Err(TeeError::not_available(
            "this machine has no usable TPM, so it cannot hold its own key. Run it as a delegated \
             machine under a human or institution controller instead",
        ));
    }
    if secret.is_empty() {
        return Err(TeeError::not_available("refusing to seal an empty secret"));
    }
    ensure_parent()?;
    std::fs::create_dir_all(dir)
        .map_err(|e| TeeError::not_available(format!("creating {}: {e}", dir.display())))?;

    let pub_path = dir.join(SEALED_PUB).to_string_lossy().into_owned();
    let priv_path = dir.join(SEALED_PRIV).to_string_lossy().into_owned();

    run(
        "tpm2_create",
        &[
            "-C",
            PARENT_HANDLE,
            "-g",
            "sha256",
            // A keyedhash object with no signing/decrypt use is a sealed data
            // blob: the TPM stores the bytes and will only give them back.
            "-u",
            &pub_path,
            "-r",
            &priv_path,
            "-i",
            "-",
        ],
        Some(secret),
    )?;

    // The blobs are ciphertext, but there is no reason for anyone but the node
    // to read them.
    restrict(&dir.join(SEALED_PUB));
    restrict(&dir.join(SEALED_PRIV));
    Ok(())
}

/// Recover a secret previously sealed by [`seal`] on this same TPM.
///
/// # Errors
///
/// [`TeeError::NotAvailable`] when the blobs are absent, or when the TPM
/// declines to unseal them — which is what a blob copied from another machine
/// looks like, and is the property the whole module exists for.
pub fn unseal(dir: &Path) -> Result<Zeroizing<Vec<u8>>> {
    if !tpm_available() {
        return Err(TeeError::not_available(
            "no usable TPM on this host, so a sealed key cannot be recovered here",
        ));
    }
    let pub_path = dir.join(SEALED_PUB);
    let priv_path = dir.join(SEALED_PRIV);
    if !pub_path.exists() || !priv_path.exists() {
        return Err(TeeError::not_available(format!(
            "no sealed key under {}",
            dir.display()
        )));
    }
    ensure_parent()?;

    let ctx = tempfile::Builder::new()
        .prefix("tenzro-tpm-sealed")
        .tempfile()
        .map_err(|e| TeeError::not_available(format!("temp file: {e}")))?;
    let ctx_path = ctx.path().to_string_lossy().into_owned();

    run(
        "tpm2_load",
        &[
            "-C",
            PARENT_HANDLE,
            "-u",
            &pub_path.to_string_lossy(),
            "-r",
            &priv_path.to_string_lossy(),
            "-c",
            &ctx_path,
        ],
        None,
    )?;
    let secret = run("tpm2_unseal", &["-c", &ctx_path], None)?;
    Ok(Zeroizing::new(secret))
}

/// Whether a sealed key is present under `dir`.
pub fn is_sealed(dir: &Path) -> bool {
    dir.join(SEALED_PUB).exists() && dir.join(SEALED_PRIV).exists()
}

/// Narrow a file to owner-only, best effort.
fn restrict(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every assertion below needs real hardware. Skipping rather than failing
    /// keeps the suite green on build hosts with no TPM, which is most of them
    /// — and the skip is loud so a TPM-equipped host that silently stopped
    /// exercising this is visible in the output.
    fn require_tpm() -> bool {
        if tpm_available() {
            return true;
        }
        eprintln!("SKIP: no usable TPM on this host");
        false
    }

    #[test]
    fn a_sealed_secret_comes_back_intact() {
        if !require_tpm() {
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let secret = b"tenzro machine signing key, 32 b";

        seal(dir.path(), secret).expect("seal");
        assert!(is_sealed(dir.path()));
        let recovered = unseal(dir.path()).expect("unseal");
        assert_eq!(&recovered[..], secret);
    }

    /// The property the module exists for: what lands on disk is not the key.
    /// If it were, sealing would have bought nothing over a keyfile.
    #[test]
    fn the_plaintext_never_appears_on_disk() {
        if !require_tpm() {
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let secret = b"an unmistakable needle in the blob";
        seal(dir.path(), secret).expect("seal");

        for name in [SEALED_PUB, SEALED_PRIV] {
            let bytes = std::fs::read(dir.path().join(name)).expect("read blob");
            assert!(
                bytes.windows(secret.len()).all(|w| w != secret.as_slice()),
                "{name} contained the plaintext"
            );
        }
    }

    #[test]
    fn sealing_is_reproducible_across_separate_objects() {
        if !require_tpm() {
            return;
        }
        let a = tempfile::tempdir().expect("tempdir");
        let b = tempfile::tempdir().expect("tempdir");
        seal(a.path(), b"first").expect("seal a");
        seal(b.path(), b"second").expect("seal b");

        assert_eq!(&unseal(a.path()).expect("unseal a")[..], b"first");
        assert_eq!(&unseal(b.path()).expect("unseal b")[..], b"second");
    }

    #[test]
    fn an_absent_blob_is_reported_rather_than_guessed() {
        if !require_tpm() {
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(!is_sealed(dir.path()));
        let err = unseal(dir.path()).expect_err("nothing to unseal");
        assert!(err.to_string().contains("no sealed key"), "{err}");
    }

    /// A blob whose private half has been tampered with must not unseal. This
    /// is the same refusal a blob copied from another machine gets, and it is
    /// what makes the key unextractable rather than merely inconvenient.
    #[test]
    fn a_tampered_blob_will_not_unseal() {
        if !require_tpm() {
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        seal(dir.path(), b"protected material").expect("seal");

        let priv_path = dir.path().join(SEALED_PRIV);
        let mut blob = std::fs::read(&priv_path).expect("read");
        let last = blob.len() - 1;
        blob[last] ^= 0xff;
        std::fs::write(&priv_path, &blob).expect("write");

        assert!(
            unseal(dir.path()).is_err(),
            "a tampered blob must not yield a key"
        );
    }

    #[test]
    fn an_empty_secret_is_refused() {
        if !require_tpm() {
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(seal(dir.path(), b"").is_err());
    }
}
