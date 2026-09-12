//! Seal a secret to this machine's Apple Secure Enclave, mirroring the
//! `tpm_seal` API so a caller can seal to whichever hardware root the host has.
//!
//! "Sealing" here is AES-256-GCM under a key derived (HKDF-SHA256) from the
//! Secure Enclave machine root (`tenzro_secure_enclave::machine_root_ikm`).
//! That root is generated once from the OS CSPRNG and immediately sealed inside
//! the SEP; its bytes never exist on disk in the clear, and a copied disk
//! yields a blob no other machine's enclave can reproduce the key for. So the
//! guarantee matches the TPM path: **machine-bound**, not merely
//! machine-resident — a copied key directory does not become a working identity
//! on another host.
//!
//! Available only on Apple hardware with a usable Secure Enclave; every entry
//! point is a no-op / `not_available` elsewhere, so the caller can probe
//! [`available`] and fall through to the next custody tier exactly as it does
//! for the TPM.

use std::path::Path;

use crate::error::{Result, TeeError};

/// On-disk name of the sealed blob within the seal directory. Distinct from the
/// TPM seal's file names so the two schemes never collide in one directory.
const SE_SEALED_BLOB: &str = "se-sealed.bin";

/// HKDF label separating the at-rest wrapping key from every other purpose
/// derived off the same machine root. Reuse the label and you reuse the key.
const WRAP_LABEL: &[u8] = b"tenzro/se-seal/at-rest/v1";
const WRAP_INFO: &[u8] = b"tenzro se-seal aes-256-gcm wrap key";

/// Whether this host can seal to a Secure Enclave.
///
/// True only on Apple hardware whose SEP is usable. The caller uses this to
/// decide whether to attempt SE sealing before falling through to the next
/// custody tier — the same shape as `tpm_seal::tpm_available`.
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub fn available() -> bool {
    tenzro_secure_enclave::available()
}

/// No Secure Enclave off Apple hardware. `tenzro-secure-enclave` is an
/// Apple-only dependency (see this crate's `Cargo.toml`), so the module cannot
/// even name it here — hence a cfg split rather than a runtime check.
#[cfg(not(any(target_os = "macos", target_os = "ios")))]
pub fn available() -> bool {
    false
}

/// Derive the AES-256 wrapping key from the Secure Enclave machine root.
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn wrap_key() -> Result<[u8; 32]> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let ikm = tenzro_secure_enclave::machine_root_ikm()
        .map_err(|e| TeeError::not_available(format!("no Secure Enclave machine root: {e}")))?;
    let hk = Hkdf::<Sha256>::new(Some(WRAP_LABEL), ikm.as_slice());
    let mut key = [0u8; 32];
    hk.expand(WRAP_INFO, &mut key)
        .map_err(|e| TeeError::CryptoError(format!("HKDF expand failed: {e}")))?;
    Ok(key)
}

/// Off Apple hardware there is no machine root to derive from. Callers reach
/// this only by ignoring [`available`]; returning an error keeps the failure
/// legible instead of sealing under a key with no hardware behind it.
#[cfg(not(any(target_os = "macos", target_os = "ios")))]
fn wrap_key() -> Result<[u8; 32]> {
    Err(TeeError::not_available(
        "Secure Enclave sealing is available only on Apple hardware",
    ))
}

/// Seal `secret` to the Secure Enclave, writing the wrapped blob into `dir`.
///
/// On-disk format: `nonce(12) || AES-256-GCM(secret)` — the ciphertext already
/// carries its 16-byte tag. The wrapping key is derived from the SEP-bound
/// machine root and is never written anywhere.
pub fn seal(dir: &Path, secret: &[u8]) -> Result<()> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};

    if !available() {
        return Err(TeeError::not_available(
            "this machine has no usable Secure Enclave, so it cannot hold its own key. Run it as \
             a delegated machine under a human or institution controller instead",
        ));
    }
    if secret.is_empty() {
        return Err(TeeError::not_available("refusing to seal an empty secret"));
    }

    let key = wrap_key()?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| TeeError::CryptoError(format!("aes-256-gcm key: {e}")))?;

    let mut nonce_bytes = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ct = cipher
        .encrypt(nonce, secret)
        .map_err(|e| TeeError::CryptoError(format!("seal encrypt: {e}")))?;

    std::fs::create_dir_all(dir)
        .map_err(|e| TeeError::not_available(format!("creating {}: {e}", dir.display())))?;
    let blob_path = dir.join(SE_SEALED_BLOB);
    let mut out = Vec::with_capacity(nonce_bytes.len() + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    std::fs::write(&blob_path, &out)
        .map_err(|e| TeeError::not_available(format!("write {}: {e}", blob_path.display())))?;
    restrict(&blob_path);
    Ok(())
}

/// Unseal the blob written by [`seal`]. Fails on a blob produced by a different
/// enclave — that is the point: a copied directory does not become a working
/// identity on another machine.
pub fn unseal(dir: &Path) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};

    if !available() {
        return Err(TeeError::not_available(
            "no usable Secure Enclave on this host, so a Secure-Enclave-sealed key cannot be \
             opened here",
        ));
    }
    let blob_path = dir.join(SE_SEALED_BLOB);
    let blob = std::fs::read(&blob_path)
        .map_err(|e| TeeError::not_available(format!("read {}: {e}", blob_path.display())))?;
    if blob.len() < 12 + 16 {
        return Err(TeeError::CryptoError(
            "Secure-Enclave-sealed blob is too short to contain a nonce and tag".into(),
        ));
    }
    let (nonce_bytes, ct) = blob.split_at(12);

    let key = wrap_key()?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| TeeError::CryptoError(format!("aes-256-gcm key: {e}")))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    let pt = cipher
        .decrypt(nonce, ct)
        .map_err(|e| TeeError::CryptoError(format!("unseal decrypt: {e}")))?;
    Ok(zeroize::Zeroizing::new(pt))
}

/// Whether a Secure-Enclave-sealed blob is present under `dir`.
pub fn is_sealed(dir: &Path) -> bool {
    dir.join(SE_SEALED_BLOB).exists()
}

/// Narrow a file to owner-only, best effort. Windows has no POSIX mode bits to
/// restrict here — but this module only ever runs on Apple hardware anyway.
fn restrict(_path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(_path, std::fs::Permissions::from_mode(0o600));
    }
}

#[cfg(all(test, any(target_os = "macos", target_os = "ios")))]
mod tests {
    use super::*;

    /// End to end on real Apple hardware: seal, then unseal, then confirm the
    /// plaintext round-trips and the on-disk blob is not the plaintext.
    #[test]
    fn seal_round_trips_and_hides_the_secret() {
        if !available() {
            return; // no SEP in this CI environment
        }
        let dir = std::env::temp_dir().join(format!("tenzro-se-seal-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let secret = b"node identity signing seed";
        seal(&dir, secret).expect("seal");
        assert!(is_sealed(&dir));

        let blob = std::fs::read(dir.join(SE_SEALED_BLOB)).unwrap();
        assert_ne!(&blob[12..], &secret[..], "blob must not be the plaintext");

        let opened = unseal(&dir).expect("unseal");
        assert_eq!(opened.as_slice(), secret);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
