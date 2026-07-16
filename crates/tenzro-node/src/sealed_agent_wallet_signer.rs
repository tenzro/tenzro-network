//! Node-layer [`HybridSigner`] over a TEE-sealed agent keypair.
//!
//! This is the autonomous-machine custody backend. It is the join point
//! between two crates that never depend on each other:
//!
//! - `tenzro-tee` owns [`AgentKeyHandle`] — a keypair whose Ed25519 scalar
//!   and ML-DSA-65 seed are both derived from a TEE-rooted IKM (distinct
//!   HKDF info strings, single hardware root) and never leave the enclave
//!   in raw form.
//! - `tenzro-wallet` owns the [`HybridSigner`] seam and the
//!   [`HybridSignatureBytes`] shape the rest of the node verifies.
//!
//! `tenzro-node` is the only crate that sees both, so the adapter lives
//! here — mirroring [`crate::mpc_threshold_signer::NodeThresholdSigner`],
//! which closes the same gap for the bridge's `ThresholdSigner`.
//!
//! A machine wallet backed by this signer mints the hybrid pair from a
//! key the node cannot read, instead of reconstructing FROST shares +
//! the ML-DSA seed into node memory (`Keystore::load_shares`). Both legs
//! sign the same message bytes; the classical leg is 64-byte Ed25519, the
//! PQ leg is 3309-byte ML-DSA-65.

use std::sync::Arc;

use async_trait::async_trait;
use tenzro_tee::AgentKeyHandle;
use tenzro_wallet::error::WalletError;
use tenzro_wallet::signing::{HybridSignatureBytes, HybridSigner};

/// [`HybridSigner`] backed by a sealed [`AgentKeyHandle`].
///
/// Construct one per autonomous-machine wallet from the handle sealed at
/// machine registration. Cloning is cheap — the handle shares its backing
/// secrets behind `Arc`.
pub struct SealedAgentWalletSigner {
    handle: Arc<AgentKeyHandle>,
}

impl SealedAgentWalletSigner {
    /// Wrap a sealed agent key handle as the machine wallet's hybrid
    /// signing backend.
    pub fn new(handle: Arc<AgentKeyHandle>) -> Self {
        Self { handle }
    }

    /// The agent DID this signer was sealed against.
    pub fn agent_did(&self) -> &str {
        self.handle.agent_did()
    }

    /// The sealed BLS12-381 verifying key (48 bytes). Not part of the
    /// [`HybridSigner`] seam — the wallet's hybrid signature is
    /// Ed25519 + ML-DSA-65 only — but the watch-only machine wallet
    /// still carries a BLS verifying key to satisfy the structural
    /// invariant and to stand in as the vote-aggregation key if the
    /// machine ever stakes. Sourced from the same enclave root.
    pub fn bls_verifying_key(&self) -> Vec<u8> {
        self.handle.bls_verifying_key()
    }
}

#[async_trait]
impl HybridSigner for SealedAgentWalletSigner {
    fn classical_public_key(&self) -> Vec<u8> {
        self.handle.pubkey().to_vec()
    }

    fn pq_verifying_key(&self) -> Vec<u8> {
        self.handle.pq_verifying_key()
    }

    async fn sign_hybrid(&self, message: &[u8]) -> Result<HybridSignatureBytes, WalletError> {
        let sig = self.handle.sign_hybrid(message);
        Ok(HybridSignatureBytes::new(sig.classical, sig.pq))
    }
}
