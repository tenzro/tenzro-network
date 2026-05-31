//! TEE-sealed secp256k1 signing keys for production EVM signers.
//!
//! This module bridges the gap between hardware-rooted TEE key derivation
//! (AMD SEV-SNP `SNP_GET_DERIVED_KEY`, Intel TDX MRTD measurement) and the
//! standard `k256` ECDSA signing API used throughout the bridge crate.
//!
//! # Why TEE-sealed keys?
//!
//! The bridge's EVM signer holds a long-lived secp256k1 private key in
//! process memory. A memory disclosure (Meltdown-class side channel, kernel
//! exploit, OS-level privilege escalation) would let an attacker steal the
//! key and drain bridge-locked funds. TEE-sealing makes the key derivable
//! only inside the enclave, bound to the VM's measured initial state — the
//! same VM image redeploys to the same key, but another tenant's VM (or a
//! tampered image) cannot recover it.
//!
//! # Derivation chain
//!
//! ```text
//!   AMD SEV-SNP path:
//!     SNP_GET_DERIVED_KEY(MEASUREMENT|IMAGE_ID|GUEST_SVN) → 64-byte IKM
//!         ↓ HKDF-SHA256(salt=label, info="tenzro/sealed-secp256k1/v1")
//!     32-byte secp256k1 scalar → k256::SecretKey
//!
//!   Intel TDX path:
//!     TDX quote → MRTD (48 bytes SHA-384) as IKM
//!         ↓ HKDF-SHA256(salt=label, info="tenzro/sealed-secp256k1/v1")
//!     32-byte secp256k1 scalar → k256::SecretKey
//! ```
//!
//! The `label` parameter provides per-purpose domain separation. Two
//! different labels produce two unrelated keys from the same TEE platform
//! — the bridge signer, an MPC share signer, and a settlement signer can
//! all derive isolated keys from the same enclave.
//!
//! # Production posture
//!
//! - No simulation fallback. Per Tenzro's no-simulation-on-testnet
//!   policy, this module returns `TeeError::NotAvailable` on dev
//!   machines rather than fabricating fake key material.
//! - Secret key bytes are wrapped in [`zeroize::Zeroizing`] and wiped on
//!   drop. `SealedSecp256k1Key` does not implement `Clone` or `Debug` for
//!   the secret material — only the public-side fields.
//! - On the rare event that the HKDF output is not a valid secp256k1
//!   scalar (≥ curve order or zero), the constructor returns an error
//!   rather than silently retrying with a different label.

use hkdf::Hkdf;
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use k256::SecretKey;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{Result, TeeError};

/// HKDF info string. Bumped if the derivation chain ever changes.
const HKDF_INFO: &[u8] = b"tenzro/sealed-secp256k1/v1";

/// A secp256k1 signing key whose private scalar is derived from TEE-rooted
/// material and never touches the filesystem or network.
///
/// The secret key lives in heap-allocated memory wrapped by
/// [`zeroize::Zeroizing`], so `Drop` zeroes it. The struct is intentionally
/// neither `Clone` nor `Debug` to prevent accidental disclosure.
pub struct SealedSecp256k1Key {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    address: [u8; 20],
}

impl SealedSecp256k1Key {
    /// Derives a key on AMD SEV-SNP via `SNP_GET_DERIVED_KEY`.
    ///
    /// The PSP-derived 64-byte key is bound to the VM's `MEASUREMENT`,
    /// `IMAGE_ID`, and `GUEST_SVN` so the key is reproducible only inside
    /// this exact VM image.
    ///
    /// `label` is the HKDF salt — use distinct labels for different
    /// purposes (e.g. `b"tenzro/bridge/evm-signer"` vs `b"tenzro/mpc"`).
    #[cfg(feature = "amd-sev-snp")]
    pub fn derive_from_snp(label: &[u8]) -> Result<Self> {
        use crate::amd_sev_snp::{guest_field_select, AmdSevSnpProvider};

        let provider = AmdSevSnpProvider::new();
        let ikm = provider.derived_key(
            0, // root_key_select = 0 → VCEK (versioned chip endorsement key)
            guest_field_select::MEASUREMENT
                | guest_field_select::IMAGE_ID
                | guest_field_select::GUEST_SVN,
            0, // vmpl = 0
            0, // guest_svn = 0 (current)
            0, // tcb_version = 0 (current)
        )?;
        let ikm = Zeroizing::new(ikm);
        Self::from_ikm(label, ikm.as_slice())
    }

    /// Derives a key on Intel TDX from MRTD (initial TD measurement).
    ///
    /// Unlike SNP, TDX has no hardware KDF — we use MRTD itself as IKM
    /// and run it through HKDF-SHA256 with the per-purpose label as salt.
    /// Two TDs with the same image have the same MRTD; tampering with the
    /// boot media changes MRTD; another tenant's TD has a different MRTD.
    ///
    /// Note: a TD operator with debug access to their own running TD can
    /// read MRTD via the same ioctl — the security boundary here is "no
    /// other tenant or compromised host OS can recover this key", not
    /// "even the TD owner cannot recover this key".
    #[cfg(feature = "intel-tdx")]
    pub async fn derive_from_tdx(label: &[u8]) -> Result<Self> {
        let provider = crate::intel_tdx::IntelTdxProvider::new();
        let mr_td = provider.platform_measurement().await?;
        let ikm = Zeroizing::new(mr_td);
        Self::from_ikm(label, ikm.as_slice())
    }

    /// Auto-detects the available TEE and derives accordingly. Returns
    /// `TeeError::NotAvailable` if neither SNP nor TDX is reachable.
    ///
    /// Order of preference: SEV-SNP (true hardware KDF), then TDX
    /// (measurement-bound HKDF).
    pub async fn derive_auto(label: &[u8]) -> Result<Self> {
        #[cfg(feature = "amd-sev-snp")]
        {
            if std::path::Path::new("/dev/sev-guest").exists() {
                return Self::derive_from_snp(label);
            }
        }
        #[cfg(feature = "intel-tdx")]
        {
            if std::path::Path::new("/dev/tdx_guest").exists()
                || std::path::Path::new("/sys/kernel/config/tsm/report").exists()
            {
                return Self::derive_from_tdx(label).await;
            }
        }
        Err(TeeError::not_available(
            "No TEE available for sealed secp256k1 key derivation",
        ))
    }

    /// Internal: wraps an IKM (either SNP's 64-byte derived key or TDX's
    /// 48-byte MRTD) into HKDF-SHA256 and produces a 32-byte secp256k1
    /// scalar.
    fn from_ikm(label: &[u8], ikm: &[u8]) -> Result<Self> {
        let hk = Hkdf::<Sha256>::new(Some(label), ikm);
        let mut scalar_bytes = Zeroizing::new([0u8; 32]);
        hk.expand(HKDF_INFO, scalar_bytes.as_mut())
            .map_err(|e| TeeError::CryptoError(format!("HKDF expand failed: {}", e)))?;

        let secret = SecretKey::from_bytes((&*scalar_bytes).into()).map_err(|e| {
            TeeError::CryptoError(format!(
                "HKDF output is not a valid secp256k1 scalar: {}",
                e
            ))
        })?;

        let signing_key = SigningKey::from(&secret);
        let verifying_key = *signing_key.verifying_key();
        let address = derive_eth_address(&verifying_key);

        Ok(Self {
            signing_key,
            verifying_key,
            address,
        })
    }

    /// 20-byte Ethereum-style address (last 20 bytes of Keccak-256 of the
    /// uncompressed public key with the 0x04 prefix stripped).
    pub fn address(&self) -> [u8; 20] {
        self.address
    }

    /// 65-byte uncompressed SEC1 encoding (`0x04 || X || Y`).
    pub fn pubkey_uncompressed(&self) -> [u8; 65] {
        let point = self.verifying_key.to_encoded_point(false);
        let bytes = point.as_bytes();
        debug_assert_eq!(bytes.len(), 65);
        let mut out = [0u8; 65];
        out.copy_from_slice(bytes);
        out
    }

    /// Signs a 32-byte digest (e.g. Keccak-256 of an RLP-encoded
    /// transaction). Returns the ECDSA signature plus the recovery id
    /// needed to construct an Ethereum signature `v`.
    pub fn sign_prehash(&self, digest: &[u8; 32]) -> Result<(Signature, RecoveryId)> {
        // PrehashSigner::sign_prehash returns Signature only — recovery id
        // is derived via try_sign_recoverable_prehash on SigningKey.
        self.signing_key
            .sign_prehash_recoverable(digest)
            .map_err(|e| TeeError::CryptoError(format!("ECDSA sign failed: {}", e)))
    }
}

/// Computes the Ethereum address from a secp256k1 verifying key.
fn derive_eth_address(vk: &VerifyingKey) -> [u8; 20] {
    use sha3::{Digest as Sha3Digest, Keccak256};
    let point = vk.to_encoded_point(false);
    let pubkey_bytes = point.as_bytes();
    // Strip the 0x04 SEC1 prefix; Keccak-256 over the 64-byte (X || Y) tail.
    let hash = Keccak256::digest(&pubkey_bytes[1..]);
    let mut out = [0u8; 20];
    out.copy_from_slice(&hash[12..32]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_ikm_deterministic() {
        // Two derivations with the same label and IKM must produce the
        // same key. This is what guarantees "redeploy → same address".
        let ikm = [0x42u8; 64];
        let label = b"tenzro/test/v1";
        let k1 = SealedSecp256k1Key::from_ikm(label, &ikm).unwrap();
        let k2 = SealedSecp256k1Key::from_ikm(label, &ikm).unwrap();
        assert_eq!(k1.address(), k2.address());
        assert_eq!(k1.pubkey_uncompressed(), k2.pubkey_uncompressed());
    }

    #[test]
    fn test_label_provides_domain_separation() {
        let ikm = [0x42u8; 64];
        let k1 = SealedSecp256k1Key::from_ikm(b"label-a", &ikm).unwrap();
        let k2 = SealedSecp256k1Key::from_ikm(b"label-b", &ikm).unwrap();
        assert_ne!(k1.address(), k2.address());
    }

    #[test]
    fn test_ikm_provides_isolation() {
        let label = b"tenzro/test/v1";
        let k1 = SealedSecp256k1Key::from_ikm(label, &[0x11u8; 64]).unwrap();
        let k2 = SealedSecp256k1Key::from_ikm(label, &[0x22u8; 64]).unwrap();
        assert_ne!(k1.address(), k2.address());
    }

    #[test]
    fn test_address_format() {
        let key = SealedSecp256k1Key::from_ikm(b"test", &[0x11u8; 64]).unwrap();
        let addr = key.address();
        assert_eq!(addr.len(), 20);
        // Cross-check via a fresh recompute — guards against accidental
        // mutation in derive_eth_address.
        let recomputed = derive_eth_address(&key.verifying_key);
        assert_eq!(addr, recomputed);
    }

    #[test]
    fn test_sign_and_verify_prehash() {
        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        let key = SealedSecp256k1Key::from_ikm(b"test", &[0x33u8; 64]).unwrap();
        let digest = [0x99u8; 32];
        let (sig, _recovery) = key.sign_prehash(&digest).unwrap();
        // Verifying with the matching public key must succeed.
        key.verifying_key
            .verify_prehash(&digest, &sig)
            .expect("self-verification");
    }

    #[test]
    fn test_pubkey_uncompressed_starts_with_0x04() {
        let key = SealedSecp256k1Key::from_ikm(b"test", &[0x44u8; 64]).unwrap();
        let pk = key.pubkey_uncompressed();
        assert_eq!(pk[0], 0x04);
        assert_eq!(pk.len(), 65);
    }

    #[test]
    fn test_derive_auto_off_hardware_returns_not_available() {
        // On dev machines without /dev/sev-guest or /dev/tdx_guest,
        // derive_auto must NOT silently fabricate a key. No-simulation
        // policy on testnet.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(SealedSecp256k1Key::derive_auto(b"test"));
        // Either NotAvailable (typical dev/CI) or Ok(_) when this very
        // test runs inside a SEV/TDX VM.
        match result {
            Err(TeeError::NotAvailable(_)) => {}
            Ok(_) => {
                let on_sev = std::path::Path::new("/dev/sev-guest").exists();
                let on_tdx = std::path::Path::new("/dev/tdx_guest").exists()
                    || std::path::Path::new("/sys/kernel/config/tsm/report").exists();
                assert!(
                    on_sev || on_tdx,
                    "derive_auto returned Ok off TEE hardware — must not happen"
                );
            }
            Err(other) => panic!("unexpected error: {:?}", other),
        }
    }
}
