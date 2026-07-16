//! Hybrid signature output type for tenzro-wallet.
//!
//! Per the post-quantum migration plan (`docs/security/quantum-resistance-migration-plan.md`)
//! every Tenzro-issued signature carries both a classical (Ed25519/Secp256k1)
//! leg and an ML-DSA-65 (FIPS 204) leg. The wallet service produces this
//! type from `sign_transaction` / `sign_data`; admission gates verify both
//! legs against the matching `pq_public_key` carried in `Transaction`.

use crate::error::WalletError;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// A backend that mints a hybrid (classical + ML-DSA-65) signature without
/// the wallet service reconstructing key shares.
///
/// This is the custody seam for wallets whose secret never enters node
/// memory: the human device signer (P-256 enclave + keychain-sealed PQ
/// seed) and the autonomous-machine sealed-agent signer (TEE-derived
/// Ed25519 + ML-DSA-65) both implement it. Where the server-custodial path
/// runs `Keystore::load_shares` → FROST → ML-DSA in node memory, a
/// `HybridSigner` produces the same [`HybridSignatureBytes`] shape from a
/// key the node cannot read.
///
/// Object-safe and transport-agnostic on purpose — the node layer wires the
/// concrete backend (which may await a TEE call or a device round-trip)
/// behind `Arc<dyn HybridSigner>`, mirroring the bridge's `ThresholdSigner`
/// seam. Both legs sign the same message bytes; callers pass the canonical
/// preimage (e.g. `Transaction::hash()` bytes or a mandate preimage).
#[async_trait]
pub trait HybridSigner: Send + Sync {
    /// The classical public key (Ed25519 32B or Secp256k1) this signer's
    /// classical leg verifies against.
    fn classical_public_key(&self) -> Vec<u8>;

    /// The ML-DSA-65 verifying-key bytes (1952 bytes) this signer's PQ leg
    /// verifies against.
    fn pq_verifying_key(&self) -> Vec<u8>;

    /// Mint a hybrid signature over `message`. Both legs sign the same bytes.
    async fn sign_hybrid(&self, message: &[u8]) -> Result<HybridSignatureBytes, WalletError>;
}

/// Output of a hybrid wallet signing operation.
///
/// The `classical` leg is the threshold MPC signature bytes (Ed25519 64B or
/// Secp256k1 64B depending on `KeyType`). The `pq` leg is the ML-DSA-65
/// signature bytes (always 3309 bytes; see `tenzro_crypto::pq::ML_DSA_65_SIG_LEN`).
///
/// Both legs are mandatory — there is no classical-only fallback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridSignatureBytes {
    /// Classical (threshold MPC) signature bytes.
    pub classical: Vec<u8>,
    /// ML-DSA-65 (FIPS 204) signature bytes (3309 bytes).
    pub pq: Vec<u8>,
}

impl HybridSignatureBytes {
    /// Construct a hybrid signature from raw bytes.
    pub fn new(classical: Vec<u8>, pq: Vec<u8>) -> Self {
        Self { classical, pq }
    }
}
