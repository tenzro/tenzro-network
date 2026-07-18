//! Shared secp256k1 ECDSA threshold-multisig verifier used by inbound
//! bridge adapters (LayerZero DVN, CCIP RMN ARM blessing, deBridge DLN
//! validator set, Hyperlane ISM, Axelar gateway). All four protocols
//! follow the same shape:
//!
//!   - A fixed set of authorised validators is configured per origin
//!     chain / per OApp / per RMN curse domain.
//!   - Inbound messages carry `(validator_addr20, sig65)` pairs over a
//!     32-byte prehash.
//!   - Delivery requires `threshold`-many distinct signatures whose
//!     recovered EVM-style addresses appear in the authorised set.
//!
//! This module factors the threshold-quorum check out of the
//! per-adapter code so we can build the LZ V2 Uln302, CCIP commit-store
//! and RMN, and deBridge DLN inbound verifiers without copy-pasting
//! cryptographic primitives. The implementation is universal — no cloud,
//! no platform gating, just k256 ECDSA and Keccak-256 address derivation.
//!
//! # Authorship boundary
//!
//! The `prehash` parameter is whatever the calling protocol's spec
//! defines:
//!
//! - **Hyperlane ISM:** `keccak256(domain || origin || id)` over the
//!   canonical Mailbox body.
//! - **LayerZero V2 ULN:** `keccak256(headerHash || payloadHash)` per
//!   `ReceiveUln302.verify`.
//! - **Chainlink CCIP commit-store:** `keccak256(commitReport)` per
//!   `CommitStore.verify`, with RMN blessing as the second-layer
//!   ARM check.
//! - **deBridge DLN:** `keccak256(submissionId || dstChainId)` per the
//!   deBridge gate Submission shape.
//! - **Axelar gateway:** `keccak256(payloadHash)` over the GMP call.

use std::collections::HashSet;

use k256::ecdsa::{RecoveryId, Signature as K256Sig, VerifyingKey};
use k256::elliptic_curve::sec1::ToSec1Point;
use sha3::{Digest as Sha3Digest, Keccak256};

use crate::error::{BridgeError, Result};

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
    /// so logs distinguish LayerZero / CCIP / deBridge / etc rejections.
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
        if signatures.len() < self.threshold as usize {
            return Err(BridgeError::AdapterError(format!(
                "{}: {} signatures < threshold {}",
                self.label,
                signatures.len(),
                self.threshold
            )));
        }
        let mut seen: HashSet<[u8; 20]> = HashSet::new();
        let mut valid_count: u8 = 0;
        for (claimed_addr, sig_bytes) in signatures {
            if !self.validators.contains(claimed_addr) {
                continue;
            }
            if !seen.insert(*claimed_addr) {
                continue;
            }
            let recovery_id_byte = sig_bytes[64];
            let v = if recovery_id_byte >= 27 {
                recovery_id_byte - 27
            } else {
                recovery_id_byte
            };
            let recovery_id = match RecoveryId::from_byte(v) {
                Some(r) => r,
                None => continue,
            };
            let sig = match K256Sig::from_slice(&sig_bytes[..64]) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let recovered = match VerifyingKey::recover_from_prehash(
                prehash, &sig, recovery_id,
            ) {
                Ok(vk) => vk,
                Err(_) => continue,
            };
            let pk_point = k256::PublicKey::from(&recovered);
            let encoded = pk_point.to_sec1_point(false);
            let pk_uncompressed = encoded.as_bytes();
            if pk_uncompressed.len() < 65 {
                continue;
            }
            let mut k = Keccak256::new();
            Sha3Digest::update(&mut k, &pk_uncompressed[1..65]);
            let hash: [u8; 32] = k.finalize().into();
            let recovered_addr: [u8; 20] = hash[12..32].try_into().unwrap();
            if recovered_addr != *claimed_addr {
                continue;
            }
            valid_count = valid_count.saturating_add(1);
            if valid_count >= self.threshold {
                return Ok(());
            }
        }
        Err(BridgeError::AdapterError(format!(
            "{}: only {} valid signatures < threshold {}",
            self.label, valid_count, self.threshold
        )))
    }
}

/// Parse a trailing `(u8 sig_count, [validator_addr20 || sig65; sig_count])`
/// signature trailer from the tail of an inbound payload. Returns
/// `(body_slice, parsed_signatures)`. This wire shape is shared by
/// Hyperlane ISM and Axelar gateway metadata; LayerZero and deBridge
/// use a different layout and decode their own trailers.
pub fn parse_trailing_signature_set(
    payload: &[u8],
) -> Result<(&[u8], Vec<([u8; 20], [u8; 65])>)> {
    let n = payload.len();
    if n < 1 {
        return Err(BridgeError::InvalidParameter(
            "secp256k1_multisig: payload too short for sig_count byte".into(),
        ));
    }
    let sig_count = payload[n - 1] as usize;
    let sig_record_len = 20 + 65;
    let trailer_len = 1 + sig_count * sig_record_len;
    if n < trailer_len + 1 {
        return Err(BridgeError::InvalidParameter(format!(
            "secp256k1_multisig: payload truncated for declared signature count {}",
            sig_count
        )));
    }
    let body = &payload[..n - trailer_len];
    let mut signatures: Vec<([u8; 20], [u8; 65])> = Vec::with_capacity(sig_count);
    for i in 0..sig_count {
        let off = n - trailer_len + i * sig_record_len;
        let mut a = [0u8; 20];
        a.copy_from_slice(&payload[off..off + 20]);
        let mut s = [0u8; 65];
        s.copy_from_slice(&payload[off + 20..off + 20 + 65]);
        signatures.push((a, s));
    }
    Ok((body, signatures))
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
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
        let addrs = vec![
            addr_for(sk1.verifying_key()),
            addr_for(sk2.verifying_key()),
        ];
        let set = ValidatorSet::new(addrs, 2, "test-set");
        let prehash = [9u8; 32];
        let sigs = vec![signed_pair(&sk1, &prehash)];
        assert!(set.verify_quorum(&prehash, &sigs).is_err());
    }

    #[test]
    fn quorum_rejects_unauthorised_signer() {
        let sk_authorised = sk_from_seed(1);
        let sk_attacker = sk_from_seed(2);
        let set = ValidatorSet::new(
            vec![addr_for(sk_authorised.verifying_key())],
            1,
            "test-set",
        );
        let prehash = [9u8; 32];
        let sigs = vec![signed_pair(&sk_attacker, &prehash)];
        assert!(set.verify_quorum(&prehash, &sigs).is_err());
    }

    #[test]
    fn quorum_rejects_duplicate_signer() {
        let sk1 = sk_from_seed(1);
        let sk2 = sk_from_seed(2);
        let set = ValidatorSet::new(
            vec![
                addr_for(sk1.verifying_key()),
                addr_for(sk2.verifying_key()),
            ],
            2,
            "test-set",
        );
        let prehash = [9u8; 32];
        let dup = signed_pair(&sk1, &prehash);
        let sigs = vec![dup, dup];
        assert!(set.verify_quorum(&prehash, &sigs).is_err());
    }

    #[test]
    fn parse_trailing_signature_set_roundtrips() {
        let body = b"body-bytes-arbitrary";
        let sk = sk_from_seed(1);
        let pair = signed_pair(&sk, &[0u8; 32]);

        let mut payload = body.to_vec();
        payload.extend_from_slice(&pair.0);
        payload.extend_from_slice(&pair.1);
        payload.push(1u8); // sig_count

        let (parsed_body, parsed_sigs) = parse_trailing_signature_set(&payload).unwrap();
        assert_eq!(parsed_body, body);
        assert_eq!(parsed_sigs.len(), 1);
        assert_eq!(parsed_sigs[0].0, pair.0);
        assert_eq!(parsed_sigs[0].1, pair.1);
    }
}
