//! MPC session setup — `InstanceId` and `MpcParameters`.
//!
//! Every DKLS23 round (DKG, signing, refresh) is identified by a 32-byte
//! `InstanceId` domain-separated by Tenzro tag `tenzro/mpc/instance/v1`. The
//! input mixture pins the session to a concrete *finalized* chain context and
//! a fresh nonce so two distinct co-signing groups cannot replay or splice
//! each other's transcripts:
//!
//! ```text
//! InstanceId = SHA-256(
//!     "tenzro/mpc/instance/v1"
//!  || finalized_block_hash   (32 bytes)
//!  || message_hash           (32 bytes, SHA-256 of the payload to sign;
//!                             zero for DKG / refresh sessions where there
//!                             is no payload yet)
//!  || session_nonce          (32 bytes, locally generated; uniqueness
//!                             enforced by the storage layer)
//! )
//! ```
//!
//! `MpcParameters` carries the curve choice (always secp256k1 for bridge
//! signing) and the `(threshold, total_parties)` shape — both stamped into
//! every persisted keyshare envelope and round message so a stale receiver
//! can reject mismatched configurations immediately.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tenzro_types::Hash;

/// Domain-separation tag for every `InstanceId` derivation.
pub const INSTANCE_DOMAIN_TAG: &[u8] = b"tenzro/mpc/instance/v1";

/// Length of a DKLS23 session `InstanceId` (SHA-256 output).
pub const INSTANCE_ID_LEN: usize = 32;

/// Length of a session nonce (the only locally-generated input to
/// `InstanceId`; everything else is consensus-anchored).
pub const SESSION_NONCE_LEN: usize = 32;

/// Domain-separated identifier of a single MPC session.
///
/// Constructed via [`InstanceId::derive`]. Two sessions with the same
/// `(finalized_block_hash, message_hash, session_nonce)` mixture produce
/// byte-identical IDs — the caller is responsible for picking fresh nonces
/// (the storage layer enforces uniqueness at insertion time).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct InstanceId(pub [u8; INSTANCE_ID_LEN]);

impl InstanceId {
    /// Derive an `InstanceId` from its four inputs.
    ///
    /// `message_hash` is the SHA-256 of the payload to sign for signing
    /// sessions. Pass `[0u8; 32]` for DKG and refresh sessions where there
    /// is no payload to anchor against.
    pub fn derive(
        finalized_block_hash: &Hash,
        message_hash: &[u8; 32],
        session_nonce: &[u8; SESSION_NONCE_LEN],
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(INSTANCE_DOMAIN_TAG);
        hasher.update(finalized_block_hash.as_bytes());
        hasher.update(message_hash);
        hasher.update(session_nonce);
        let digest = hasher.finalize();
        let mut out = [0u8; INSTANCE_ID_LEN];
        out.copy_from_slice(&digest);
        Self(out)
    }

    /// 32-byte view for hashing / equality.
    pub fn as_bytes(&self) -> &[u8; INSTANCE_ID_LEN] {
        &self.0
    }

    /// Hex view for logging and storage keys.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Debug for InstanceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "InstanceId({})", self.to_hex())
    }
}

impl std::fmt::Display for InstanceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Curve choice for an MPC session. Bridge signing is always secp256k1; the
/// enum exists so storage records carry a discriminant against future
/// curve additions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MpcCurve {
    /// secp256k1 (DKLS23 over k256 — bridge signer).
    Secp256k1,
}

/// `(threshold, total_parties)` parameter pair shared across all rounds of
/// one keyshare's lifetime. Stamped into every keyshare envelope and round
/// message so a receiver can reject mismatched configurations immediately.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MpcParameters {
    /// Curve discriminant.
    pub curve: MpcCurve,
    /// Signing threshold `t` — at least `t` parties must cooperate to
    /// produce a signature.
    pub threshold: u8,
    /// Total party count `n` — there are exactly `n` keyshares in the
    /// distribution. Invariant: `2 <= threshold <= total_parties <= 32`.
    pub total_parties: u8,
}

impl MpcParameters {
    /// Construct a parameter bundle. Returns `None` if the invariant
    /// `2 <= threshold <= total_parties <= 32` is violated.
    ///
    /// The `threshold >= 2` lower bound matches the upstream DKLS23
    /// `Parameters::new` invariant — at `t == 1` the scheme degenerates
    /// to a single-party signer with no threshold protection.
    pub fn new(curve: MpcCurve, threshold: u8, total_parties: u8) -> Option<Self> {
        if threshold < 2 || threshold > total_parties || total_parties > 32 {
            return None;
        }
        Some(Self {
            curve,
            threshold,
            total_parties,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_id_is_deterministic_for_same_inputs() {
        let block = Hash::from_bytes(&[7u8; 32]).unwrap();
        let msg = [9u8; 32];
        let nonce = [3u8; SESSION_NONCE_LEN];

        let a = InstanceId::derive(&block, &msg, &nonce);
        let b = InstanceId::derive(&block, &msg, &nonce);
        assert_eq!(a, b);
    }

    #[test]
    fn instance_id_differs_when_block_hash_changes() {
        let msg = [9u8; 32];
        let nonce = [3u8; SESSION_NONCE_LEN];
        let a = InstanceId::derive(&Hash::from_bytes(&[1u8; 32]).unwrap(), &msg, &nonce);
        let b = InstanceId::derive(&Hash::from_bytes(&[2u8; 32]).unwrap(), &msg, &nonce);
        assert_ne!(a, b);
    }

    #[test]
    fn instance_id_differs_when_nonce_changes() {
        let block = Hash::from_bytes(&[7u8; 32]).unwrap();
        let msg = [9u8; 32];
        let a = InstanceId::derive(&block, &msg, &[1u8; SESSION_NONCE_LEN]);
        let b = InstanceId::derive(&block, &msg, &[2u8; SESSION_NONCE_LEN]);
        assert_ne!(a, b);
    }

    #[test]
    fn mpc_parameters_rejects_zero_threshold() {
        assert!(MpcParameters::new(MpcCurve::Secp256k1, 0, 3).is_none());
    }

    #[test]
    fn mpc_parameters_rejects_threshold_one() {
        // Upstream DKLS23 `Parameters::new` requires t >= 2 — match it here
        // so the conversion to `dkls23_core::Parameters` cannot fail at
        // runtime.
        assert!(MpcParameters::new(MpcCurve::Secp256k1, 1, 3).is_none());
    }

    #[test]
    fn mpc_parameters_rejects_threshold_above_total() {
        assert!(MpcParameters::new(MpcCurve::Secp256k1, 4, 3).is_none());
    }

    #[test]
    fn mpc_parameters_rejects_total_above_32() {
        assert!(MpcParameters::new(MpcCurve::Secp256k1, 2, 33).is_none());
    }

    #[test]
    fn mpc_parameters_accepts_2_of_3() {
        let p = MpcParameters::new(MpcCurve::Secp256k1, 2, 3).unwrap();
        assert_eq!(p.threshold, 2);
        assert_eq!(p.total_parties, 3);
    }
}
