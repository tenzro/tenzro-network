//! An identity a machine cannot lose.
//!
//! Sealing a randomly generated key to the TPM protects it well: the blob is
//! worthless on any other machine, so a stolen disk yields nothing. What it does
//! not survive is the blob going away. Delete the data directory — which any
//! administrator, any reinstall, any misfired `rm` can do — and the secret is
//! gone, because the only copy was in the file. The node comes back as somebody
//! new, and everything that knew it must be told again.
//!
//! That is the wrong failure. A machine's identity should be a property of the
//! machine, and the only thing entitled to revoke it is an administrator
//! clearing the TPM from firmware. Anything short of that — a wiped disk, a
//! fresh install, a deleted directory — should leave the machine exactly who it
//! was.
//!
//! ## How the identity is recomputed instead of stored
//!
//! A TPM hierarchy is rooted in a seed that never leaves the chip and does not
//! change. `TPM2_CreatePrimary` derives a key from that seed and the template it
//! is given, by a fixed KDF: the same seed and the same template always produce
//! the same key. Nothing is written down, because nothing needs to be — the key
//! is regenerated on demand.
//!
//! So this derives, rather than generates:
//!
//! 1. A primary signing key in the owner hierarchy, from a template pinned in
//!    [`TEMPLATE`]. Same chip, same template, same key.
//! 2. A signature over a fixed label, using RSASSA — the one signature scheme
//!    here that is deterministic, because PKCS#1 v1.5 padding contains no
//!    randomness. ECDSA would produce a different signature every time and is
//!    useless for this.
//! 3. HKDF over that signature, with a per-purpose label, giving as many
//!    independent 32-byte secrets as the node needs from one trip to the chip.
//!
//! The signature never leaves this process and the primary's private half never
//! leaves the chip. What an attacker with the template gets is nothing: they
//! would need the hierarchy seed, which is not extractable.
//!
//! ## What still changes the identity, and nothing else
//!
//! Clearing the TPM — `tpm2_clear`, or the firmware setup screen — replaces the
//! owner seed and therefore every key under it. That is the deliberate escape
//! hatch: an administrator with physical presence can retire a machine's
//! identity, and no software path can. Replacing the chip or the board does the
//! same, for the same reason.
//!
//! ## The cost, and why the cached copy stays
//!
//! Deriving the primary means the TPM generating an RSA key, and on the
//! hardware this was written for that takes about twenty-one seconds. Once per
//! recovery is fine; once per boot would not be, and once per key would be
//! absurd. So the sealed copy is still written and still read first — it is a
//! cache now rather than the only record, and the derivation is what refills it
//! when it is gone.

use crate::error::{Result as TeeResult, TeeError};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use zeroize::Zeroizing;

/// Which hierarchy the primary is derived under.
///
/// The **endorsement** hierarchy, not the owner (storage) hierarchy, because
/// only one of them survives a `TPM2_Clear`.
///
/// `TPM2_Clear` regenerates the Storage Primary Seed and leaves the
/// Endorsement Primary Seed untouched — only `TPM2_ChangeEPS`, which needs
/// platform authorization, replaces the EPS. An owner-hierarchy primary is
/// therefore destroyed by any TPM clear, and a TPM clear is not an exotic
/// event: it is what UEFI's "Clear TPM" menu item does, and per the TCG
/// Physical Presence Interface that firmware path issues
/// `TPM2_ClearControl(NO)` first, so even setting `disableClear` does not
/// prevent it. An identity that a routine firmware menu can destroy is not
/// persistent.
///
/// TCG's own device-identity guidance recommends exactly this: create the
/// device identity as a primary in the endorsement hierarchy so it "can be
/// recreated at any time during the lifetime of the TPM", and it lists
/// destruction-by-clear as a denial-of-service threat whose countermeasure is
/// re-creatable keys. Systems that root device identity in the storage
/// hierarchy forfeit that for nothing.
///
/// What still retires a machine: `TPM2_ChangeEPS` (platform auth), replacing
/// the TPM or the board that holds its non-volatile state, and a vendor
/// firmware update that deliberately rolls the EPS. Retiring stays possible;
/// it stops being accidental.
const HIERARCHY: &str = "e";

/// The template the primary is derived from.
///
/// Every field is load-bearing and none may change without changing every
/// identity derived from it, so it is written here once and referred to rather
/// than spelled out at each call site.
///
/// - `rsa2048` because RSASSA needs RSA, and 2048 is what a TPM of this era
///   generates in a tolerable time.
/// - `rsassa-sha256` because it is deterministic. This is the whole reason the
///   scheme works.
/// - `null` for the symmetric algorithm: this key signs, it does not wrap.
pub const TEMPLATE: &str = "rsa2048:rsassa-sha256:null";

/// The attributes the primary is created with. Pinned for the same reason.
///
/// `sign` because it must sign; `sensitivedataorigin` because the TPM makes the
/// key rather than being handed one; `fixedtpm|fixedparent` because it must not
/// be duplicable to another chip — an identity that could be moved is not an
/// identity.
pub const ATTRIBUTES: &str = "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign";

/// What gets signed to produce the root secret.
///
/// Versioned, so a future change of scheme can derive a different identity
/// deliberately rather than by accident. `v2` is the endorsement-hierarchy
/// root: moving off the owner hierarchy changed which seed the primary comes
/// from, so every identity derived under `v1` is a different key and the label
/// says so rather than leaving two incompatible roots sharing one name.
pub const ROOT_LABEL: &[u8] = b"tenzro/node-identity/v2/root";

/// HKDF salt separating this KDF's output from any other use of the root.
///
/// Deliberately *not* versioned alongside [`ROOT_LABEL`]. The version belongs
/// on the thing that determines the root — the label that gets signed — and
/// this is a fixed domain separator applied to whatever root that produced.
/// Bumping it in lockstep would rotate every derived key a second time for a
/// change that alters nothing about the derivation's meaning.
const HKDF_SALT: &[u8] = b"tenzro/node-identity/v1";

/// The derived root, kept for the life of the process.
///
/// One trip to the chip, however many keys are wanted. Without this a node with
/// five identity keys would spend nearly two minutes deriving them one at a
/// time, and would do it again on the next start.
static ROOT: Mutex<Option<Zeroizing<Vec<u8>>>> = Mutex::new(None);

/// Whether this machine can derive an identity it cannot lose.
pub fn derivation_available() -> bool {
    (Path::new("/dev/tpmrm0").exists() || Path::new("/dev/tpm0").exists())
        && which_tool("tpm2_createprimary").is_some()
        && which_tool("tpm2_sign").is_some()
}

fn which_tool(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join(name))
            .find(|candidate| candidate.is_file())
    })
}

fn run(tool: &str, args: &[&str]) -> TeeResult<Vec<u8>> {
    let out = Command::new(tool)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| TeeError::KeyGenerationFailed(format!("running {tool}: {e}")))?;
    if !out.status.success() {
        return Err(TeeError::KeyGenerationFailed(format!(
            "{tool} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(out.stdout)
}

/// The secret this machine derives from its own chip.
///
/// Deterministic: the same machine returns the same bytes for ever, and a
/// different machine cannot return them at all.
fn root_secret() -> TeeResult<Zeroizing<Vec<u8>>> {
    // The lock is held across the trip to the chip, not merely around the
    // cache read. Releasing it first let every concurrent first-caller miss
    // the cache and start its own derivation: a node bringing up four network
    // services paid four full `TPM2_CreatePrimary` calls (about three seconds
    // each on this class of chip) which the TPM then serialised anyway, and
    // startup blew past bind deadlines. Holding it means one thread does the
    // work and the rest wait for its result, which is what the cache was for.
    let mut guard = ROOT
        .lock()
        .map_err(|_| TeeError::KeyGenerationFailed("the identity root lock is poisoned".into()))?;
    if let Some(cached) = guard.clone() {
        return Ok(cached);
    }

    let dir = tempfile::Builder::new()
        .prefix("tenzro-derive")
        .tempdir()
        .map_err(|e| TeeError::KeyGenerationFailed(format!("temporary directory: {e}")))?;
    let ctx = dir.path().join("primary.ctx");
    let label = dir.path().join("label");
    let sig = dir.path().join("sig");
    std::fs::write(&label, ROOT_LABEL)
        .map_err(|e| TeeError::KeyGenerationFailed(format!("writing the label: {e}")))?;

    run(
        "tpm2_createprimary",
        &[
            "-C", HIERARCHY,
            "-G", TEMPLATE,
            "-g", "sha256",
            "-a", ATTRIBUTES,
            "-c", &ctx.to_string_lossy(),
        ],
    )?;
    run(
        "tpm2_sign",
        &[
            "-c", &ctx.to_string_lossy(),
            "-g", "sha256",
            "-s", "rsassa",
            "-o", &sig.to_string_lossy(),
            &label.to_string_lossy(),
        ],
    )?;

    let bytes = Zeroizing::new(
        std::fs::read(&sig).map_err(|e| TeeError::KeyGenerationFailed(format!("reading the signature: {e}")))?,
    );
    if bytes.len() < 32 {
        return Err(TeeError::KeyGenerationFailed(
            "the chip returned too little material to derive from".into(),
        ));
    }
    *guard = Some(bytes.clone());
    Ok(bytes)
}

/// A 32-byte secret for one purpose, derived from this machine's chip.
///
/// Independent per purpose: knowing one tells an attacker nothing about
/// another, which is why each key gets its own rather than everything sharing
/// one and being distinguished by convention.
pub fn derive_secret(purpose: &str) -> TeeResult<Zeroizing<[u8; 32]>> {
    let root = root_secret()?;
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(HKDF_SALT), &root);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(purpose.as_bytes(), out.as_mut())
        .map_err(|e| TeeError::KeyGenerationFailed(format!("expanding the derived secret: {e}")))?;
    Ok(out)
}

/// Forget the cached root. For tests, and for a process that has finished with
/// identity material and would rather not keep it about.
pub fn forget_cached_root() {
    if let Ok(mut g) = ROOT.lock() {
        *g = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_template_is_pinned_because_every_identity_depends_on_it() {
        // Changing any of this changes every identity ever derived from it, so
        // a change should have to be deliberate enough to break this test.
        //
        // It last fired for real when the root moved to the endorsement
        // hierarchy and `ROOT_LABEL` went v1 -> v2. That was the correct
        // change and this assertion was left behind, so the guard sat red
        // instead of guarding. Both constants are pinned now, and the salt is
        // pinned separately precisely because it does *not* track the version.
        assert_eq!(TEMPLATE, "rsa2048:rsassa-sha256:null");
        assert_eq!(ROOT_LABEL, b"tenzro/node-identity/v2/root");
        assert_eq!(HKDF_SALT, b"tenzro/node-identity/v1");
        assert!(ATTRIBUTES.contains("fixedtpm"), "an identity that can move is not one");
        assert!(ATTRIBUTES.contains("fixedparent"));
    }

    /// The root must hang off the endorsement hierarchy.
    ///
    /// The owner hierarchy's seed is regenerated by `TPM2_Clear` — a UEFI menu
    /// item — so an owner-rooted identity is destroyed by a routine firmware
    /// action. The endorsement seed survives it. This is the property the whole
    /// module exists for, and it is one character wide.
    #[test]
    fn the_root_is_endorsement_rooted() {
        assert_eq!(
            HIERARCHY, "e",
            "the identity root must be in the endorsement hierarchy; the owner \
             hierarchy's seed does not survive TPM2_Clear"
        );
    }

    #[test]
    fn the_signature_scheme_must_be_the_deterministic_one() {
        // RSASSA is PKCS#1 v1.5, whose padding contains no randomness, so the
        // same message signs to the same bytes every time. ECDSA does not, and
        // would silently produce a different identity on every call.
        assert!(TEMPLATE.contains("rsassa"));
        assert!(!TEMPLATE.contains("ecdsa"));
        assert!(!TEMPLATE.contains("rsapss"), "PSS is randomised");
    }

    #[test]
    fn purposes_are_independent() {
        // Derived without a chip: the expansion is what is under test here, and
        // it is the part that decides whether one leaked key exposes another.
        let root = Zeroizing::new(vec![7u8; 256]);
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(HKDF_SALT), &root);
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        hk.expand(b"validator", &mut a).unwrap();
        hk.expand(b"bls", &mut b).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn the_same_root_and_purpose_always_give_the_same_secret() {
        // The property the whole design rests on.
        let root = Zeroizing::new(vec![9u8; 256]);
        let derive = |p: &[u8]| {
            let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(HKDF_SALT), &root);
            let mut out = [0u8; 32];
            hk.expand(p, &mut out).unwrap();
            out
        };
        assert_eq!(derive(b"validator"), derive(b"validator"));
    }

    #[test]
    fn a_different_root_gives_a_different_identity() {
        // Which is what makes clearing the TPM an effective retirement, and
        // what stops another machine impersonating this one.
        let mut out = [[0u8; 32]; 2];
        for (i, seed) in [1u8, 2u8].into_iter().enumerate() {
            let root = Zeroizing::new(vec![seed; 256]);
            let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(HKDF_SALT), &root);
            hk.expand(b"validator", &mut out[i]).unwrap();
        }
        assert_ne!(out[0], out[1]);
    }

    #[test]
    fn availability_is_reported_rather_than_assumed() {
        // A machine with no chip must be told, not left to fail later with
        // something unrelated.
        let _ = derivation_available();
    }
}
