//! Secp256k1 ECDSA threshold-multisig verifier for route committees.
//!
//!   - A fixed set of authorised validators is named by the governed route.
//!   - A delivery carries `(validator_addr20, sig65)` pairs over a 32-byte
//!     prehash.
//!   - Delivery requires `threshold`-many distinct signatures whose
//!     recovered EVM-style addresses appear in the authorised set.
//!
//! The prehash every committee signs is
//! [`crate::route::attestation::attestation_digest`], which binds this
//! chain's id, the route, the nonce and an expiry, so a signature made for
//! one route verifies for no other.

use std::collections::HashSet;

use k256::ecdsa::{RecoveryId, Signature as K256Sig, VerifyingKey};
use k256::elliptic_curve::sec1::ToSec1Point;
use sha3::{Digest as Sha3Digest, Keccak256};

use crate::error::{BridgeError, Result};

/// The EVM-style address that signed `prehash` with `sig` (`r || s || v`,
/// `v` raw 0/1 or 27/28), or `None` for a signature that does not recover.
pub fn recover_address(prehash: &[u8; 32], sig: &[u8; 65]) -> Option<[u8; 20]> {
    let v = if sig[64] >= 27 { sig[64] - 27 } else { sig[64] };
    let recovery_id = RecoveryId::from_byte(v)?;
    let signature = K256Sig::from_slice(&sig[..64]).ok()?;
    let recovered = VerifyingKey::recover_from_prehash(prehash, &signature, recovery_id).ok()?;
    let encoded = k256::PublicKey::from(&recovered).to_sec1_point(false);
    let pk = encoded.as_bytes();
    if pk.len() < 65 {
        return None;
    }
    let mut k = Keccak256::new();
    Sha3Digest::update(&mut k, &pk[1..65]);
    let hash: [u8; 32] = k.finalize().into();
    hash[12..32].try_into().ok()
}

/// A threshold secp256k1-ECDSA validator set scoped to one origin
/// domain or one OApp config — the calling adapter owns the
/// scoping key (origin domain id, OApp address, RMN curse domain
/// id, etc).
#[derive(Debug, Clone)]
pub struct ValidatorSet {
    /// Authorised validator addresses (20-byte secp256k1 EVM-style).
    pub validators: Vec<[u8; 20]>,
    /// Quorum threshold (count of distinct signatures required).
    pub threshold: u8,
    /// Adapter-friendly label used in error messages.
    pub label: &'static str,
}

impl ValidatorSet {
    /// Build a new validator set. `label` is folded into error messages
    /// so logs distinguish which committee rejected.
    pub fn new(validators: Vec<[u8; 20]>, threshold: u8, label: &'static str) -> Self {
        Self {
            validators,
            threshold,
            label,
        }
    }

    /// Verify that `signatures` contains `threshold`-many distinct
    /// validators in the configured set with valid secp256k1 signatures
    /// over `prehash`. Each signature MUST be 65 bytes
    /// `(r32 || s32 || v1)`; the recovery-id byte may be 0/1 (raw) or
    /// 27/28 (EIP-155-style) and is normalised internally.
    pub fn verify_quorum(
        &self,
        prehash: &[u8; 32],
        signatures: &[([u8; 20], [u8; 65])],
    ) -> Result<()> {
        // A zero threshold would admit any single valid signature, and a
        // threshold above the set size can never be met; both are
        // configuration errors, refused rather than evaluated.
        if self.threshold == 0 || self.threshold as usize > self.validators.len() {
            return Err(BridgeError::AdapterError(format!(
                "{}: threshold {} is not within 1..={}",
                self.label,
                self.threshold,
                self.validators.len()
            )));
        }
        if signatures.len() < self.threshold as usize {
            return Err(BridgeError::AdapterError(format!(
                "{}: {} signatures < threshold {}",
                self.label,
                signatures.len(),
                self.threshold
            )));
        }
        let valid_count = self.valid_signers(prehash, signatures).len();
        if valid_count >= self.threshold as usize {
            return Ok(());
        }
        Err(BridgeError::AdapterError(format!(
            "{}: only {} valid signatures < threshold {}",
            self.label, valid_count, self.threshold
        )))
    }

    /// The members of the set with a valid secp256k1 signature over
    /// `prehash` in `signatures`, each once, in the order given.
    pub fn valid_signers(
        &self,
        prehash: &[u8; 32],
        signatures: &[([u8; 20], [u8; 65])],
    ) -> Vec<[u8; 20]> {
        let mut seen: HashSet<[u8; 20]> = HashSet::new();
        let mut valid = Vec::new();
        for (claimed_addr, sig_bytes) in signatures {
            if !self.validators.contains(claimed_addr) {
                continue;
            }
            if !seen.insert(*claimed_addr) {
                continue;
            }
            if recover_address(prehash, sig_bytes) != Some(*claimed_addr) {
                continue;
            }
            valid.push(*claimed_addr);
        }
        valid
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::{SigningKey, signature::hazmat::PrehashSigner};
    use k256::elliptic_curve::sec1::ToSec1Point;
    use sha3::{Digest as Sha3Digest, Keccak256};

    /// Deterministic signing keys from a 32-byte seed so the tests
    /// don't depend on the workspace's `k256` 0.14-rc randomness wiring.
    fn sk_from_seed(seed: u8) -> SigningKey {
        let bytes = [seed.max(1); 32];
        SigningKey::from_bytes((&bytes).into()).expect("valid scalar")
    }

    fn addr_for(vk: &VerifyingKey) -> [u8; 20] {
        let pk_point = k256::PublicKey::from(vk);
        let encoded = pk_point.to_sec1_point(false);
        let pk_uncompressed = encoded.as_bytes();
        let mut k = Keccak256::new();
        Sha3Digest::update(&mut k, &pk_uncompressed[1..65]);
        let hash: [u8; 32] = k.finalize().into();
        let mut out = [0u8; 20];
        out.copy_from_slice(&hash[12..32]);
        out
    }

    fn signed_pair(sk: &SigningKey, prehash: &[u8; 32]) -> ([u8; 20], [u8; 65]) {
        let (sig, rec): (K256Sig, RecoveryId) = sk
            .sign_prehash(prehash)
            .expect("k256 prehash sign must succeed for valid prehash");
        let addr = addr_for(sk.verifying_key());
        let mut out = [0u8; 65];
        out[..64].copy_from_slice(&sig.to_bytes());
        out[64] = rec.to_byte();
        (addr, out)
    }

    #[test]
    fn quorum_admits_threshold_distinct_signers() {
        let sk1 = sk_from_seed(1);
        let sk2 = sk_from_seed(2);
        let sk3 = sk_from_seed(3);
        let addrs = vec![
            addr_for(sk1.verifying_key()),
            addr_for(sk2.verifying_key()),
            addr_for(sk3.verifying_key()),
        ];
        let set = ValidatorSet::new(addrs, 2, "test-set");
        let prehash = [9u8; 32];
        let sigs = vec![signed_pair(&sk1, &prehash), signed_pair(&sk2, &prehash)];
        set.verify_quorum(&prehash, &sigs).unwrap();
    }

    #[test]
    fn quorum_rejects_below_threshold() {
        let sk1 = sk_from_seed(1);
        let sk2 = sk_from_seed(2);
        let addrs = vec![addr_for(sk1.verifying_key()), addr_for(sk2.verifying_key())];
        let set = ValidatorSet::new(addrs, 2, "test-set");
        let prehash = [9u8; 32];
        let sigs = vec![signed_pair(&sk1, &prehash)];
        assert!(set.verify_quorum(&prehash, &sigs).is_err());
    }

    #[test]
    fn quorum_rejects_unauthorised_signer() {
        let sk_authorised = sk_from_seed(1);
        let sk_attacker = sk_from_seed(2);
        let set = ValidatorSet::new(vec![addr_for(sk_authorised.verifying_key())], 1, "test-set");
        let prehash = [9u8; 32];
        let sigs = vec![signed_pair(&sk_attacker, &prehash)];
        assert!(set.verify_quorum(&prehash, &sigs).is_err());
    }

    #[test]
    fn quorum_rejects_duplicate_signer() {
        let sk1 = sk_from_seed(1);
        let sk2 = sk_from_seed(2);
        let set = ValidatorSet::new(
            vec![addr_for(sk1.verifying_key()), addr_for(sk2.verifying_key())],
            2,
            "test-set",
        );
        let prehash = [9u8; 32];
        let dup = signed_pair(&sk1, &prehash);
        let sigs = vec![dup, dup];
        assert!(set.verify_quorum(&prehash, &sigs).is_err());
    }

    #[test]
    fn a_zero_or_unreachable_threshold_refuses_even_valid_signatures() {
        let sk1 = sk_from_seed(1);
        let prehash = [9u8; 32];
        let sigs = vec![signed_pair(&sk1, &prehash)];
        let zero = ValidatorSet::new(vec![addr_for(sk1.verifying_key())], 0, "test-set");
        assert!(zero.verify_quorum(&prehash, &sigs).is_err());
        let unreachable = ValidatorSet::new(vec![addr_for(sk1.verifying_key())], 2, "test-set");
        assert!(unreachable.verify_quorum(&prehash, &sigs).is_err());
    }
}
