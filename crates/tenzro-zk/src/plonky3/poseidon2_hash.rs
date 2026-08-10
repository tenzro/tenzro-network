//! Native (off-circuit) Poseidon2 hashing over [`KoalaBear`].
//!
//! Used wherever a circuit's witness needs to be committed to with the same
//! hash function the AIR uses internally — think `commitment =
//! Poseidon2(checksum)` becomes a public input that the AIR re-derives from
//! a private witness.
//!
//! The permutation is the same `Poseidon2KoalaBear<24>` used by the
//! Fiat-Shamir challenger in [`super::config`], so audits can point at one
//! set of round constants for both transcript and on-circuit hashes.
//!
//! # API
//!
//! - [`hash_one`] — single field element → 8-element digest.
//! - [`hash_many`] — slice of field elements → 8-element digest (sponge mode).
//!
//! The 8-element output corresponds to the `OUT = 8` parameter on
//! [`PaddingFreeSponge`] — a Poseidon2 capacity of 8 over a 24-wide state
//! gives 16 rate elements, leaving 8 capacity which is the Plonky3
//! convention for 100-bit collision resistance.

use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::{KoalaBear, default_koalabear_poseidon2_24};
use p3_symmetric::{CryptographicHasher, PaddingFreeSponge};

/// Width of the Poseidon2 permutation used here.
pub const STATE_WIDTH: usize = 24;
/// Sponge rate.
pub const RATE: usize = 16;
/// Digest length (number of field elements).
pub const DIGEST_LEN: usize = 8;

/// Poseidon2 sponge over a 24-wide KoalaBear state.
type Sponge = PaddingFreeSponge<
    p3_koala_bear::Poseidon2KoalaBear<STATE_WIDTH>,
    STATE_WIDTH,
    RATE,
    DIGEST_LEN,
>;

fn sponge() -> Sponge {
    Sponge::new(default_koalabear_poseidon2_24())
}

/// Hash a slice of field elements to an 8-element [`KoalaBear`] digest.
pub fn hash_many(input: &[KoalaBear]) -> [KoalaBear; DIGEST_LEN] {
    sponge().hash_iter(input.iter().copied())
}

/// Hash a single field element. Convenience wrapper for the common
/// `commitment = Hash(witness)` pattern.
pub fn hash_one(x: KoalaBear) -> [KoalaBear; DIGEST_LEN] {
    hash_many(&[x])
}

/// Compress two digests into one — for tree-style commitments where you've
/// already produced two child digests and want their parent.
pub fn hash_pair(
    left: &[KoalaBear; DIGEST_LEN],
    right: &[KoalaBear; DIGEST_LEN],
) -> [KoalaBear; DIGEST_LEN] {
    let mut input = [KoalaBear::ZERO; 2 * DIGEST_LEN];
    input[..DIGEST_LEN].copy_from_slice(left);
    input[DIGEST_LEN..].copy_from_slice(right);
    hash_many(&input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_one_is_deterministic() {
        let a = hash_one(KoalaBear::from_u64(42));
        let b = hash_one(KoalaBear::from_u64(42));
        assert_eq!(a, b);
    }

    #[test]
    fn hash_one_distinguishes_inputs() {
        let a = hash_one(KoalaBear::from_u64(1));
        let b = hash_one(KoalaBear::from_u64(2));
        assert_ne!(a, b);
    }

    #[test]
    fn hash_many_distinguishes_distinct_inputs() {
        // Note: PaddingFreeSponge does NOT length-extend; callers committing to
        // variable-length inputs must include the length explicitly. This test
        // pins the property that DIFFERENT non-zero inputs produce different
        // digests, which is the actual collision-resistance guarantee.
        let a = hash_many(&[KoalaBear::from_u64(1), KoalaBear::from_u64(2)]);
        let b = hash_many(&[KoalaBear::from_u64(2), KoalaBear::from_u64(1)]);
        assert_ne!(a, b);
    }

    #[test]
    fn hash_pair_distinguishes_order() {
        let a = hash_one(KoalaBear::from_u64(1));
        let b = hash_one(KoalaBear::from_u64(2));
        let ab = hash_pair(&a, &b);
        let ba = hash_pair(&b, &a);
        assert_ne!(ab, ba);
    }
}
