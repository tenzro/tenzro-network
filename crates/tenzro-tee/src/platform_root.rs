//! The stable hardware root every sealed key derives from.
//!
//! Sealing only means something if the same platform running the same image
//! reproduces the same key. A key that changes on restart is not sealed — it is
//! ephemeral, and anything that recorded the old public key (an ERC-8004 agent
//! record, an on-chain bridge sender address, an MPC keyshare wrapper) is now
//! pointing at material nobody holds.
//!
//! So the root must be a function of the platform's measured state and nothing
//! else. Two things that look like plausible roots but are not:
//!
//! - **Attestation quote bytes.** Fresh per call; a quote carries a timestamp
//!   and a signature over caller-supplied data.
//! - **Report identifiers.** Assigned per report, not per platform.
//!
//! What each vendor actually offers:
//!
//! | Vendor | Root | Stable across restart |
//! |---|---|---|
//! | AMD SEV-SNP | `SNP_GET_DERIVED_KEY` bound to `MEASUREMENT \| IMAGE_ID \| GUEST_SVN` | yes |
//! | Intel TDX | MRTD (initial TD measurement, 48-byte SHA-384) | yes |
//! | AWS Nitro / NVIDIA GPU CC | no key-derivation interface | — |
//!
//! SEV-SNP is the strongest of the three: the PSP runs the KDF, so the root is
//! never exposed even to the guest, and a host that tampers with the image gets
//! a different key rather than the same one. TDX has no hardware KDF, so MRTD
//! itself is the input keying material — readable inside the TD, which bounds
//! the guarantee to "no other tenant and no compromised host can recover this",
//! not "not even the TD owner can".
//!
//! Nitro and NVIDIA GPU CC have no derivation interface at all. Callers that
//! need to work there fall back to the vendor measurement carried in an
//! attestation report, which is stable for a given image; see
//! [`crate::sealed_agent_keypair`].

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{Result, TeeError};

/// HKDF `info` for [`derive_platform_key`]. Callers separate their purposes
/// through the `label` salt, not through this.
const HKDF_INFO: &[u8] = b"tenzro/platform-root/derived-key";

/// Read the platform's stable root keying material.
///
/// Returns the SEV-SNP PSP-derived key (64 bytes) when `/dev/sev-guest` is
/// present, otherwise the TDX MRTD (48 bytes) when a TDX report interface is
/// present. Both are reproducible for a given measured image.
///
/// Returns [`TeeError::NotAvailable`] on every other platform, including dev
/// machines. Nothing is fabricated when the hardware is absent — per the
/// no-simulation policy, a caller that cannot get a real root must fail rather
/// than seal against a placeholder.
pub async fn platform_root_ikm() -> Result<Zeroizing<Vec<u8>>> {
    #[cfg(feature = "amd-sev-snp")]
    {
        if std::path::Path::new("/dev/sev-guest").exists() {
            use crate::amd_sev_snp::{AmdSevSnpProvider, guest_field_select};

            let key = AmdSevSnpProvider::new().derived_key(
                0, // root_key_select = 0 → VCEK (versioned chip endorsement key)
                guest_field_select::MEASUREMENT
                    | guest_field_select::IMAGE_ID
                    | guest_field_select::GUEST_SVN,
                0, // vmpl = 0
                0, // guest_svn = 0 (current)
                0, // tcb_version = 0 (current)
            )?;
            return Ok(Zeroizing::new(key.to_vec()));
        }
    }
    #[cfg(feature = "intel-tdx")]
    {
        if std::path::Path::new("/dev/tdx_guest").exists()
            || std::path::Path::new("/sys/kernel/config/tsm/report").exists()
        {
            let mr_td = crate::intel_tdx::IntelTdxProvider::new()
                .platform_measurement()
                .await?;
            return Ok(Zeroizing::new(mr_td.to_vec()));
        }
    }
    Err(TeeError::not_available(
        "no SEV-SNP or TDX platform root available for key derivation",
    ))
}

/// Whether [`platform_root_ikm`] can return a root on this host.
///
/// A probe of the device paths only — it does not issue an ioctl, so it is
/// cheap enough to call on a hot path deciding whether to take a sealed route
/// or a measurement-only fallback.
pub fn platform_root_available() -> bool {
    #[cfg(feature = "amd-sev-snp")]
    {
        if std::path::Path::new("/dev/sev-guest").exists() {
            return true;
        }
    }
    #[cfg(feature = "intel-tdx")]
    {
        if std::path::Path::new("/dev/tdx_guest").exists()
            || std::path::Path::new("/sys/kernel/config/tsm/report").exists()
        {
            return true;
        }
    }
    false
}

/// Derive a 32-byte purpose-specific key from the platform root.
///
/// `label` is the HKDF salt and is the only thing separating one purpose from
/// another: the bridge signer, an MPC keyshare wrapper, and a settlement signer
/// all root in the same platform material and stay mutually unrecoverable
/// because their labels differ. Reuse a label and you reuse a key.
pub async fn derive_platform_key(label: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let ikm = platform_root_ikm().await?;
    let hk = Hkdf::<Sha256>::new(Some(label), ikm.as_slice());
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_INFO, out.as_mut())
        .map_err(|e| TeeError::CryptoError(format!("HKDF expand failed: {}", e)))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn root_is_absent_off_hardware() {
        // The no-simulation policy in one assertion: off SEV/TDX there is no
        // root, and no placeholder is invented to stand in for one.
        let available = platform_root_available();
        match platform_root_ikm().await {
            Ok(_) => assert!(available, "a root was produced without SEV or TDX present"),
            Err(TeeError::NotAvailable(_)) => {}
            Err(e) => assert!(available, "unexpected error off TEE hardware: {:?}", e),
        }
    }

    #[tokio::test]
    async fn derived_key_follows_the_root() {
        // Off hardware every call fails and there is nothing to compare; on
        // hardware the same label must reproduce and two labels must diverge.
        // One test covers both so it stays meaningful inside a real CVM.
        if !platform_root_available() {
            assert!(derive_platform_key(b"tenzro/test/alpha").await.is_err());
            return;
        }

        let a = derive_platform_key(b"tenzro/test/alpha").await.unwrap();
        let b = derive_platform_key(b"tenzro/test/alpha").await.unwrap();
        let c = derive_platform_key(b"tenzro/test/beta").await.unwrap();

        assert_eq!(*a, *b, "same label must reproduce");
        assert_ne!(*a, *c, "different labels must not collide");
    }
}
