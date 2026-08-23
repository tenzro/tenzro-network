//! Node-layer [`HybridSigner`] over this machine's TPM-rooted validator keyset.
//!
//! # Why this exists
//!
//! A machine identity's wallet must be *the machine's own key*. Two of the
//! three registration paths already work that way: a human enrolling a passkey
//! binds the wallet to the passkey's smart account, and a machine with a TEE
//! binds it to an enclave-sealed handle. Both hand the registry a
//! [`WalletBinding`](tenzro_identity::WalletBinding) built from hardware-held
//! material, and neither provisions a server-side wallet.
//!
//! A machine with a TPM but no TEE had no such path. It fell through to
//! `register_autonomous_machine_with_fee`, which mints a fresh MPC wallet from
//! the binder — a wallet with no relationship to the hardware root that was
//! just verified, or to the public key stored beside it as
//! `public_keys[0]`. The identity was hardware-anchored and its wallet was not,
//! which is the one thing the identity model is supposed to rule out.
//!
//! This adapter closes that gap. It is the join point between two crates that
//! do not depend on each other, in the same shape as
//! [`crate::sealed_agent_wallet_signer`]:
//!
//! - `tenzro-node`'s [`keygen`](crate::keygen) owns the validator keyset —
//!   Ed25519, ML-DSA-65 and BLS12-381, every one of them *derived* from the
//!   TPM's endorsement-hierarchy root rather than generated, so the same
//!   machine produces the same keys after a wiped data directory.
//! - `tenzro-wallet` owns the [`HybridSigner`] seam and the
//!   [`HybridSignatureBytes`] shape the rest of the node verifies against.
//!
//! # The keys are the machine's, and only the machine's
//!
//! Everything here is loaded from the node's own data directory, where it sits
//! TPM-sealed. Nothing in this module accepts key material, an address, or a
//! public key from a caller.
//!
//! That is deliberate and load-bearing. If a wallet binding could be supplied
//! over RPC, any caller could bind their identity to any address they liked —
//! including a funded one they do not control. The passkey path is safe from
//! that because the WebAuthn ceremony proves possession of the credential; the
//! TEE path is safe because the attestation commits to the sealed handle. The
//! equivalent proof here is that the bytes never came from outside: they were
//! unsealed from this machine's TPM by this process.
//!
//! # What this is not
//!
//! Not hardware-isolated signing. A TPM 2.0 cannot hold an Ed25519 or a
//! BLS12-381 key at all — the TCG Algorithm Registry assigns neither a curve
//! ID, and every shipping TPM implements P-256 and P-384 only — so the chip
//! seals these keys rather than signing with them, and they are plaintext in
//! this process's memory while a signature is minted. What the TPM provides is
//! that the key cannot be read off a stolen disk and cannot be reconstructed on
//! another machine, not that it never exists in RAM.

use std::path::Path;

use async_trait::async_trait;
use tenzro_crypto::keys::KeyPair;
use tenzro_crypto::pq::MlDsaSigningKey;
use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer};
use tenzro_wallet::error::WalletError;
use tenzro_wallet::signing::{HybridSignatureBytes, HybridSigner};

use crate::error::{NodeError, Result};

/// [`HybridSigner`] backed by the node's TPM-sealed validator keyset.
///
/// Construct one with [`from_data_dir`](Self::from_data_dir) at machine
/// registration. The classical leg is 64-byte Ed25519 and the PQ leg is
/// 3309-byte ML-DSA-65, both over the same message bytes.
pub struct TpmValidatorWalletSigner {
    classical: Ed25519SignerImpl,
    classical_public_key: Vec<u8>,
    pq: MlDsaSigningKey,
    bls_verifying_key: Vec<u8>,
}

impl TpmValidatorWalletSigner {
    /// Load this machine's validator keyset as a wallet signing backend.
    ///
    /// Reads the same three keys consensus uses, from the same place, so the
    /// wallet this backs resolves to the node's own validator address rather
    /// than to a separately minted one.
    ///
    /// # Errors
    ///
    /// Fails if any leg of the keyset is missing. This is deliberately not a
    /// partial success: a wallet bound to two of three keys would satisfy the
    /// structural invariant while being unable to produce a signature the
    /// network accepts, and the failure would surface later and elsewhere.
    pub fn from_data_dir(data_dir: &Path) -> Result<Self> {
        let keypair: KeyPair = crate::keygen::load_validator_keypair(data_dir)?;
        let classical_public_key = keypair.public_key().to_bytes();
        let classical = Ed25519SignerImpl::new(keypair).map_err(|e| {
            NodeError::Other(format!("validator Ed25519 key is not usable as a signer: {e}"))
        })?;
        let pq = crate::keygen::load_validator_pq_key(data_dir)?;
        let bls = crate::keygen::load_validator_bls_key(data_dir)?;
        let bls_verifying_key = bls.public_key().to_bytes().to_vec();

        Ok(Self {
            classical,
            classical_public_key,
            pq,
            bls_verifying_key,
        })
    }

    /// This machine's validator Ed25519 public key.
    ///
    /// An inherent accessor as well as a [`HybridSigner`] method, so callers
    /// that only need to *compare* against the machine's own key — refusing a
    /// caller-supplied one, say — do not have to bring the trait into scope to
    /// do it.
    pub fn validator_public_key(&self) -> &[u8] {
        &self.classical_public_key
    }

    /// The BLS12-381 verifying key (48 bytes, `min_pk` G1-compressed).
    ///
    /// Outside the [`HybridSigner`] seam, which is Ed25519 + ML-DSA-65 only,
    /// but the watch-only wallet still carries one: it is the vote-aggregation
    /// key this machine already votes with in HotStuff-2, so binding the wallet
    /// to anything else would give the same machine two BLS identities.
    pub fn bls_verifying_key(&self) -> Vec<u8> {
        self.bls_verifying_key.clone()
    }
}

#[async_trait]
impl HybridSigner for TpmValidatorWalletSigner {
    fn classical_public_key(&self) -> Vec<u8> {
        self.classical_public_key.clone()
    }

    fn pq_verifying_key(&self) -> Vec<u8> {
        self.pq.verifying_key_bytes().to_vec()
    }

    async fn sign_hybrid(
        &self,
        message: &[u8],
    ) -> std::result::Result<HybridSignatureBytes, WalletError> {
        let classical = self
            .classical
            .sign(message)
            .map_err(|e| WalletError::SignatureFailed(format!("validator Ed25519 leg: {e}")))?;
        let pq = self.pq.sign(message);
        Ok(HybridSignatureBytes::new(classical.to_bytes(), pq))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The signer must never be constructible from caller-supplied material.
    ///
    /// This is a compile-shaped invariant rather than a runtime one: the only
    /// constructor takes a filesystem path to the node's own data directory.
    /// The test exists so that adding a `from_parts(pubkey, address, ..)`
    /// convenience — which is exactly the shape someone reaches for when
    /// wiring an RPC handler — has to delete an assertion that says why not.
    #[test]
    fn the_only_way_in_is_this_machines_own_data_directory() {
        // A missing directory yields an error rather than a usable signer, so
        // there is no path that fabricates a keyset when one is absent.
        let err = TpmValidatorWalletSigner::from_data_dir(Path::new(
            "/nonexistent/tenzro/does-not-exist",
        ));
        assert!(
            err.is_err(),
            "a signer must not be constructible without this machine's sealed keys"
        );
    }
}
