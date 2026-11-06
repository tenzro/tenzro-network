//! The two pinned STARK configurations.
//!
//! Both prove the same AIRs (see [`crate::circuits`]) and share no
//! cryptographic component beyond the Plonky3 uni-STARK protocol code:
//!
//! | | KoalaBear / SHA-256 | Goldilocks / BLAKE3 |
//! |---|---|---|
//! | Base field | `2^31 - 2^24 + 1` | `2^64 - 2^32 + 1` |
//! | Challenge field | degree-8 binomial extension (~2^248) | degree-5 binomial extension (~2^320) |
//! | Merkle leaf/node hash | SHA-256 | BLAKE3 |
//! | Fiat-Shamir transcript | SHA-256 | BLAKE3 |
//! | FRI rate | 1/16 | 1/32 |
//! | Queries / query PoW | 60 / 16 bits | 48 / 16 bits |
//!
//! Both use the hiding FRI PCS with salted Merkle leaves, so openings reveal
//! nothing about the witness.
//!
//! # Hash choice
//!
//! The transcript and the Merkle trees use standard byte hashes (SHA-256 and
//! BLAKE3), not an arithmetization-oriented permutation. The STARK's
//! soundness then rests on the collision and random-oracle behaviour of hashes
//! with decades of public cryptanalysis rather than on a young algebraic
//! design, at the cost of larger and slower commitments than a Poseidon-style
//! sponge would give. The two systems use different hashes so that a break in
//! either leaves the other standing. The rationale and the soundness numbers
//! are in `docs/architecture/zk-proof-systems.md`.
//!
//! # Soundness
//!
//! [`super::soundness`] computes the proven (Johnson-bound regime) security
//! of each parameter set; its tests pin both at no less than 128 bits.

use core::convert::Infallible;
use p3_challenger::{HashChallenger, SerializingChallenger32, SerializingChallenger64};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters, HidingFriPcs};
use p3_goldilocks::Goldilocks;
use p3_koala_bear::KoalaBear;
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_uni_stark::StarkConfig;
use std::sync::{Arc, Mutex};

use rand_p3::rngs::StdRng;
use rand_p3::{Rng, SeedableRng, TryRng};

use super::soundness::SystemParameters;

/// Random codewords the hiding PCS mixes into every committed batch.
const NUM_RANDOM_CODEWORDS: usize = 4;

/// A ChaCha stream seeded from the operating system, used for Merkle leaf
/// salts and trace randomization. A verifier never draws from it.
///
/// Plonky3 clones the generator it is handed (the hiding MMCS is cloned into
/// the FRI MMCS). Cloning a plain generator would duplicate its stream and
/// reuse salts across trees, so every clone here shares one stream.
#[derive(Clone)]
pub struct SaltRng(Arc<Mutex<StdRng>>);

impl SaltRng {
    fn fresh() -> Self {
        use rand::RngCore;
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        Self(Arc::new(Mutex::new(StdRng::from_seed(seed))))
    }

    fn with<T>(&self, f: impl FnOnce(&mut StdRng) -> T) -> T {
        let mut guard = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        f(&mut guard)
    }
}

impl TryRng for SaltRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(self.with(|r| r.next_u32()))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(self.with(|r| r.next_u64()))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        self.with(|r| r.fill_bytes(dst));
        Ok(())
    }
}

/// KoalaBear base field, SHA-256 commitments and transcript.
pub mod koala_bear {
    use super::*;

    /// Base field.
    pub type Val = KoalaBear;
    /// Challenge field: degree-8 extension of KoalaBear.
    pub type Challenge = BinomialExtensionField<Val, 8>;
    type ByteHash = p3_sha256::Sha256;
    type FieldHash = SerializingHasher<ByteHash>;
    type Compress = CompressionFunctionFromHasher<ByteHash, 2, 32>;
    /// Salt elements per Merkle leaf (5 × 31 bits).
    const SALT_ELEMS: usize = 5;
    type ValMmcs = MerkleTreeHidingMmcs<Val, u8, FieldHash, Compress, SaltRng, 2, 32, SALT_ELEMS>;
    type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
    type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
    type Dft = Radix2DitParallel<Val>;
    type Pcs = HidingFriPcs<Val, Dft, ValMmcs, ChallengeMmcs, SaltRng>;
    /// The pinned configuration.
    pub type Config = StarkConfig<Pcs, Challenge, Challenger>;

    /// FRI and field parameters, as fed to the soundness calculation.
    pub const PARAMETERS: SystemParameters = SystemParameters {
        base_field_bits: 30.988_684, // log2(2^31 - 2^24 + 1)
        extension_degree: 8,
        log_blowup: 4,
        num_queries: 60,
        query_pow_bits: 16,
        commit_pow_bits: 0,
    };

    /// Build the configuration.
    pub fn config() -> Config {
        let byte_hash = ByteHash {};
        let val_mmcs = ValMmcs::new(
            FieldHash::new(byte_hash),
            Compress::new(byte_hash),
            0,
            SaltRng::fresh(),
        );
        let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
        let fri = FriParameters {
            log_blowup: PARAMETERS.log_blowup,
            log_final_poly_len: 0,
            max_log_arity: 1,
            num_queries: PARAMETERS.num_queries,
            commit_proof_of_work_bits: PARAMETERS.commit_pow_bits,
            query_proof_of_work_bits: PARAMETERS.query_pow_bits,
            mmcs: challenge_mmcs,
        };
        let pcs = Pcs::new(
            Dft::default(),
            val_mmcs,
            fri,
            NUM_RANDOM_CODEWORDS,
            SaltRng::fresh(),
        );
        Config::new(pcs, Challenger::from_hasher(vec![], byte_hash))
    }
}

/// Goldilocks base field, BLAKE3 commitments and transcript.
pub mod goldilocks {
    use super::*;

    /// Base field.
    pub type Val = Goldilocks;
    /// Challenge field: degree-5 extension of Goldilocks.
    pub type Challenge = BinomialExtensionField<Val, 5>;
    type ByteHash = p3_blake3::Blake3;
    type FieldHash = SerializingHasher<ByteHash>;
    type Compress = CompressionFunctionFromHasher<ByteHash, 2, 32>;
    /// Salt elements per Merkle leaf (3 × 64 bits).
    const SALT_ELEMS: usize = 3;
    type ValMmcs = MerkleTreeHidingMmcs<Val, u8, FieldHash, Compress, SaltRng, 2, 32, SALT_ELEMS>;
    type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
    type Challenger = SerializingChallenger64<Val, HashChallenger<u8, ByteHash, 32>>;
    type Dft = Radix2DitParallel<Val>;
    type Pcs = HidingFriPcs<Val, Dft, ValMmcs, ChallengeMmcs, SaltRng>;
    /// The pinned configuration.
    pub type Config = StarkConfig<Pcs, Challenge, Challenger>;

    /// FRI and field parameters, as fed to the soundness calculation.
    pub const PARAMETERS: SystemParameters = SystemParameters {
        base_field_bits: 64.0, // log2(2^64 - 2^32 + 1), rounded
        extension_degree: 5,
        log_blowup: 5,
        num_queries: 48,
        query_pow_bits: 16,
        commit_pow_bits: 0,
    };

    /// Build the configuration.
    pub fn config() -> Config {
        let byte_hash = ByteHash {};
        let val_mmcs = ValMmcs::new(
            FieldHash::new(byte_hash),
            Compress::new(byte_hash),
            0,
            SaltRng::fresh(),
        );
        let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
        let fri = FriParameters {
            log_blowup: PARAMETERS.log_blowup,
            log_final_poly_len: 0,
            max_log_arity: 1,
            num_queries: PARAMETERS.num_queries,
            commit_proof_of_work_bits: PARAMETERS.commit_pow_bits,
            query_proof_of_work_bits: PARAMETERS.query_pow_bits,
            mmcs: challenge_mmcs,
        };
        let pcs = Pcs::new(
            Dft::default(),
            val_mmcs,
            fri,
            NUM_RANDOM_CODEWORDS,
            SaltRng::fresh(),
        );
        Config::new(pcs, Challenger::from_hasher(vec![], byte_hash))
    }
}
