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
use std::sync::OnceLock;

use zeroize::Zeroizing;

use crate::error::{Result, TeeError};

/// Filenames of the two halves of a sealed object, inside its directory.
const SEALED_PUB: &str = "sealed.pub";
const SEALED_PRIV: &str = "sealed.priv";
/// Default persistent handle the sealing parent is created at.
///
/// A *fixed* handle rather than a scan for a vacant one: the parent has to be
/// findable by every process, across reboots, for the lifetime of the sealed
/// blobs. Picking whatever is free at first use would hand a different handle
/// to a machine that had been re-provisioned, and its existing blobs — which
/// are bound to the object, not the handle — would become unloadable.
///
/// It must live in the **storage/owner** persistent range,
/// `0x81000000`-`0x8100FFFF`, because the parent is created with
/// `tpm2_createprimary -C o`. Within that range this is an arbitrary but
/// deliberate offset: clear of the conventional SRK at `0x81000001` and of the
/// low handles platform firmware and Windows provision when they take
/// ownership. It is a *default*, not an assumption — see
/// [`TENZRO_TPM_PARENT_HANDLE_ENV`] for hosts where it collides.
///
/// It used to be `0x81010001`, which is not an owner-hierarchy handle at all:
/// `0x81010000`-`0x8101FFFF` is the *endorsement* range, and `0x81010001`
/// specifically is the conventional RSA Endorsement Key handle (see
/// tpm2_createek(1)). On any TPM with a provisioned EK — every Windows machine,
/// and most others by convention — that handle is already the EK, an
/// `adminWithPolicy` object with no authValue, so `tpm2_create -C 0x81010001`
/// fails with `0x12F authValue or authPolicy is not available`.
const DEFAULT_PARENT_HANDLE: &str = "0x81000100";

/// Environment override for the sealing parent's persistent handle.
///
/// The default cannot be right everywhere: the owner range is shared with
/// firmware, other products, and site provisioning, so on some hosts it will be
/// occupied by something that is not ours. Rather than evict a stranger's key
/// or silently wander to another handle, the module refuses and the operator
/// points it somewhere free. Must be in `0x81000000`-`0x8100FFFF`.
const TENZRO_TPM_PARENT_HANDLE_ENV: &str = "TENZRO_TPM_PARENT_HANDLE";

/// Persistent handle the sealing parent lives at, honouring the override.
///
/// Resolved once per process: the handle must not change under a running node,
/// or a key sealed early would be unloadable later.
fn parent_handle() -> &'static str {
    static RESOLVED: OnceLock<String> = OnceLock::new();
    RESOLVED.get_or_init(|| {
        std::env::var(TENZRO_TPM_PARENT_HANDLE_ENV)
            .ok()
            .map(|h| h.trim().to_owned())
            .filter(|h| !h.is_empty())
            .unwrap_or_else(|| DEFAULT_PARENT_HANDLE.to_owned())
    })
}

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

/// Ensure the sealing parent exists at [`parent_handle`].
///
/// Idempotent: creating it when it is already there fails, and that failure is
/// the success case on every boot after the first. Distinguished from a real
/// error by re-probing the handle rather than by matching on the message, which
/// would break the first time the tools reworded it.
fn ensure_parent() -> Result<()> {
    if parent_exists() {
        return Ok(());
    }
    // Occupied, but by something we cannot seal under. Refuse rather than
    // evict: a persistent handle we did not create belongs to another
    // subsystem — a platform SRK, an EK, another product's key — and
    // `tpm2_evictcontrol` on it would be a destructive act on shared platform
    // state to work around our own misconfiguration. Say which handle and why,
    // because the TPM's own error for this is `0x12F` and names neither.
    if run("tpm2_readpublic", &["-c", parent_handle()], None).is_ok() {
        let handle = parent_handle();
        return Err(TeeError::not_available(format!(
            "persistent handle {handle} is already occupied by an object this node cannot use as \
             a sealing parent — it is not a userWithAuth restricted decryption key. Refusing to \
             evict it, because it belongs to another subsystem. Either clear it deliberately with \
             `tpm2_evictcontrol -C o -c {handle}` if it really is stale, or point this node at a \
             free handle in the owner range with {TENZRO_TPM_PARENT_HANDLE_ENV}."
        )));
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

    // Racy by construction: every probe above is a separate process, so two
    // nodes (or two tests) starting together can both find the handle vacant
    // and both try to claim it. The loser gets `0x14C persistent object already
    // defined`. That is not a failure — the postcondition is "a usable parent
    // is at this handle", and the winner established it. Re-probe and decide on
    // the observed state rather than on which call happened to return an error,
    // because the primary is deterministically re-derived from the TPM's seed:
    // both processes created the *same* object, so either one persisting it is
    // equally correct.
    let evicted = run(
        "tpm2_evictcontrol",
        &["-C", "o", "-c", &ctx_path, parent_handle()],
        None,
    );

    if parent_exists() {
        return Ok(());
    }

    // Only now is the eviction error a real one: nothing usable is at the
    // handle, so surface why the attempt failed rather than a bare postcondition
    // message.
    match evicted {
        Err(e) => Err(e),
        Ok(_) => Err(TeeError::not_available(format!(
            "sealing parent could not be made persistent at {}",
            parent_handle()
        ))),
    }
}

/// TPMA_OBJECT bits that decide whether a persistent object can be our parent.
const TPMA_USER_WITH_AUTH: u32 = 0x0000_0040;
const TPMA_ADMIN_WITH_POLICY: u32 = 0x0000_0080;
const TPMA_RESTRICTED: u32 = 0x0001_0000;
const TPMA_DECRYPT: u32 = 0x0002_0000;

/// Whether `handle` holds an object this module can actually seal under.
///
/// Presence is not enough, and assuming it was the second half of the EK-handle
/// bug. `tpm2_readpublic` requires no authorisation, so it succeeds against
/// *any* object — including the Endorsement Key, which is `adminWithPolicy`
/// and usable only through a policy session this module never builds. Probing
/// with `readpublic` alone therefore reported "parent ready" for an object we
/// could not use, and the real failure surfaced one call later out of
/// `tpm2_create`, naming neither the handle nor the reason.
///
/// A usable parent is a restricted decryption key we can authorise with a
/// plain auth value: `userWithAuth` set, `adminWithPolicy` clear.
fn handle_is_usable_parent(handle: &str) -> bool {
    let Ok(out) = run("tpm2_readpublic", &["-c", handle], None) else {
        return false;
    };
    let Some(attrs) = parse_object_attributes(&String::from_utf8_lossy(&out)) else {
        return false;
    };
    attrs & TPMA_USER_WITH_AUTH != 0
        && attrs & TPMA_ADMIN_WITH_POLICY == 0
        && attrs & TPMA_RESTRICTED != 0
        && attrs & TPMA_DECRYPT != 0
}

/// Pull the numeric attributes out of `tpm2_readpublic` YAML.
///
/// Reads the `raw:` line of the `attributes:` block rather than matching names
/// in the `value:` line, so a tools release that renames or reorders the
/// human-readable flags does not silently turn every parent unusable.
fn parse_object_attributes(text: &str) -> Option<u32> {
    let mut in_attributes = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("attributes:") {
            in_attributes = true;
            continue;
        }
        if in_attributes {
            if let Some(raw) = trimmed.strip_prefix("raw:") {
                return u32::from_str_radix(raw.trim().trim_start_matches("0x"), 16).ok();
            }
            // The block is `attributes:` then `value:` then `raw:`. Anything
            // else means we have walked out of it and should not keep reading.
            if !trimmed.starts_with("value:") {
                in_attributes = false;
            }
        }
    }
    None
}

/// Whether the persistent sealing parent is present *and* usable.
fn parent_exists() -> bool {
    handle_is_usable_parent(parent_handle())
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
            parent_handle(),
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

    let load_under = |parent: &str| {
        run(
            "tpm2_load",
            &[
                "-C",
                parent,
                "-u",
                &pub_path.to_string_lossy(),
                "-r",
                &priv_path.to_string_lossy(),
                "-c",
                &ctx_path,
            ],
            None,
        )
    };

    // A blob is bound to the parent it was created under. Sealing always uses
    // parent_handle(), so a blob that cannot be loaded under the current parent
    // is unusable — fail closed rather than probing any other handle.
    load_under(parent_handle()).map_err(|_| {
        TeeError::not_available(format!(
            "sealed key under {} could not be loaded under the current parent {}",
            dir.display(),
            parent_handle()
        ))
    })?;

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

    /// Parse a `0x`-prefixed handle into its numeric value.
    fn handle_value(handle: &str) -> u32 {
        u32::from_str_radix(handle.trim_start_matches("0x"), 16)
            .unwrap_or_else(|e| panic!("handle {handle} is not hex: {e}"))
    }

    #[test]
    fn the_sealing_parent_lives_in_the_owner_range() {
        // The bug this guards against cost a silent failure on every TPM host:
        // the parent is created with `tpm2_createprimary -C o`, so its
        // persistent handle must be in the storage/owner range
        // 0x81000000-0x8100FFFF. The previous value, 0x81010001, was in the
        // *endorsement* range and is by convention the RSA Endorsement Key —
        // an adminWithPolicy object no authValue can use as a parent.
        //
        // Hardware-independent on purpose: a host with no TPM must still catch
        // a handle moved back into the wrong hierarchy.
        let handle = handle_value(DEFAULT_PARENT_HANDLE);
        assert!(
            (0x8100_0000..=0x8100_FFFF).contains(&handle),
            "{DEFAULT_PARENT_HANDLE} is not in the owner-hierarchy persistent range \
             0x81000000-0x8100FFFF; a parent created with `-C o` cannot be persisted outside it"
        );
        assert_ne!(
            handle, 0x8100_0001,
            "0x81000001 is the conventional SRK handle and belongs to the platform, not to us"
        );
    }

    #[test]
    fn object_attributes_come_from_the_raw_field() {
        // Real `tpm2_readpublic` output, an SRK on an Intel fTPM. The parser
        // must read `raw:` rather than matching names in `value:`, so a tools
        // release that renames a flag cannot quietly make every parent look
        // unusable.
        let srk = "\
name: 000b1234
attributes:
  value: fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt
  raw: 0x30472
type:
  value: ecc
";
        let attrs = parse_object_attributes(srk).expect("attributes parse");
        assert_eq!(attrs, 0x30472);
        assert!(attrs & TPMA_USER_WITH_AUTH != 0);
        assert!(attrs & TPMA_ADMIN_WITH_POLICY == 0);
        assert!(attrs & TPMA_RESTRICTED != 0 && attrs & TPMA_DECRYPT != 0);
    }

    #[test]
    fn an_endorsement_key_is_rejected_as_a_parent() {
        // The EK template as this machine's TPM reports it: adminWithPolicy and
        // no userWithAuth. Presence alone said "parent ready"; the attribute
        // check is what turns that into "not usable".
        let ek = "\
attributes:
  value: fixedtpm|fixedparent|sensitivedataorigin|adminwithpolicy|restricted|decrypt
  raw: 0x300b2
";
        let attrs = parse_object_attributes(ek).expect("attributes parse");
        assert!(
            attrs & TPMA_USER_WITH_AUTH == 0 && attrs & TPMA_ADMIN_WITH_POLICY != 0,
            "an EK must not satisfy the usable-parent predicate"
        );
    }

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
