//! Hybrid signature output type for tenzro-wallet.
//!
//! Per the post-quantum migration plan (`docs/security/quantum-resistance-migration-plan.md`)
//! every Tenzro-issued signature carries both a classical (Ed25519/Secp256k1)
//! leg and an ML-DSA-65 (FIPS 204) leg. The wallet service produces this
//! type from `sign_transaction` / `sign_data`; admission gates verify both
//! legs against the matching `pq_public_key` carried in `Transaction`.

use serde::{Deserialize, Serialize};

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
