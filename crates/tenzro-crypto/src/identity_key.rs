//! The commitment an identity key makes to the key that replaces it.
//!
//! When the chain records an identity's key it may also record a digest of
//! the next one; the following key change must then reveal exactly that
//! key. A digest holds when the key in force is broken, so a stolen key
//! cannot name its own successor.

use sha2::{Digest, Sha256};

const NEXT_KEY_DOMAIN: &[u8] = b"tenzro/identity/next-key/v1";

/// The digest a key commits to for the key that replaces it:
/// `SHA-256(domain ‖ ed25519 ‖ len(ml_dsa) as u32 BE ‖ ml_dsa)`.
pub fn next_key_commitment(ed25519: &[u8; 32], ml_dsa: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(NEXT_KEY_DOMAIN);
    h.update(ed25519);
    h.update((ml_dsa.len() as u32).to_be_bytes());
    h.update(ml_dsa);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_commitment_binds_both_keys() {
        let a = next_key_commitment(&[1; 32], &[2; 1952]);
        assert_ne!(a, next_key_commitment(&[3; 32], &[2; 1952]));
        assert_ne!(a, next_key_commitment(&[1; 32], &[4; 1952]));
        assert_ne!(a, next_key_commitment(&[1; 32], &[2; 1951]));
        assert_eq!(a, next_key_commitment(&[1; 32], &[2; 1952]));
    }
}
