//! The STARK configuration of compact certificates.
//!
//! Goldilocks: the ML-DSA arithmetic multiplies two numbers below `q < 2^23`
//! and sums a few of the products, which fits a 64-bit field without
//! splitting into limbs.
//!
//! A compact certificate is permanent evidence, so its parameters target at
//! least 100 bits of provable soundness in the Johnson-bound regime, not the
//! conjectured bound:
//!
//! - the query phase: each FRI query at rate `2^-LOG_BLOWUP` contributes
//!   `-log2(sqrt(rate) (1 + 1/(2m)))` bits, plus query grinding;
//! - the commit phase: each folding round errs with probability at most
//!   `(m + 1/2)^7 n^2 / (3 rate^(3/2) |F|)` for an evaluation domain of
//!   size `n`. With `n` near `2^23` this term alone is about `2^62 / |F|`,
//!   which is why challenges live in the degree-5 extension (`|F| = 2^320`)
//!   rather than the degree-2 one, where it would cap soundness near 66 bits.
//!
//! Merkle trees hash with Keccak-f, the fastest of the available hashes on
//! a CPU prover, and commit to a cap of `2^CAP_HEIGHT` nodes so that every
//! opening path is `CAP_HEIGHT` nodes shorter.

use p3_challenger::{HashChallenger, SerializingChallenger64};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_goldilocks::Goldilocks;
use p3_keccak::{Keccak256Hash, KeccakF, VECTOR_LEN};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher};
use p3_uni_stark::StarkConfig;

/// Base field.
pub type Val = Goldilocks;
/// Challenge field.
pub type Challenge = BinomialExtensionField<Val, 5>;
/// Rate of the Merkle sponge, in `u64` cells of the Keccak-f state.
pub(crate) const LEAF_RATE: usize = 17;
pub(crate) type U64Hash = PaddingFreeSponge<KeccakF, 25, LEAF_RATE, 4>;
pub(crate) type FieldHash = SerializingHasher<U64Hash>;
type Compress = CompressionFunctionFromHasher<U64Hash, 2, 4>;
type ValMmcs = MerkleTreeMmcs<[Val; VECTOR_LEN], [u64; VECTOR_LEN], FieldHash, Compress, 2, 4>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Challenger = SerializingChallenger64<Val, HashChallenger<u8, Keccak256Hash, 32>>;
type Dft = Radix2DitParallel<Val>;
type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
/// The configuration type.
pub type CertStarkConfig = StarkConfig<Pcs, Challenge, Challenger>;

/// FRI rate `2^-LOG_BLOWUP`.
pub const LOG_BLOWUP: usize = 3;
/// Query grinding bits.
pub const QUERY_POW_BITS: usize = 16;
/// Merkle cap height.
pub const CAP_HEIGHT: usize = 6;
/// The Johnson-regime multiplicity parameter the soundness bound is taken at.
const JOHNSON_M: f64 = 16.0;
/// Bits in the challenge field.
const CHALLENGE_BITS: f64 = 320.0;
/// Domain separator of the transcript.
const TRANSCRIPT_LABEL: &[u8] = b"tenzro/compact-certificate";

/// Bits one FRI query contributes in the Johnson-bound regime.
fn bits_per_query() -> f64 {
    let rate = 2f64.powi(-(LOG_BLOWUP as i32));
    -(rate.sqrt() * (1.0 + 1.0 / (2.0 * JOHNSON_M))).log2()
}

/// Provable soundness, in bits, of `queries` FRI queries with
/// [`QUERY_POW_BITS`] of grinding over an evaluation domain of
/// `2^log_domain` points: the smaller of the query-phase and commit-phase
/// bounds.
pub fn proven_soundness_bits(queries: usize, log_domain: usize) -> f64 {
    let query = queries as f64 * bits_per_query() + QUERY_POW_BITS as f64;
    let rate = 2f64.powi(-(LOG_BLOWUP as i32));
    let rounds = (log_domain as f64 / 3.0).ceil();
    let commit_log = 7.0 * (JOHNSON_M + 0.5).log2() + 2.0 * log_domain as f64
        - (3.0 * rate.powf(1.5)).log2()
        + rounds.log2();
    let commit = CHALLENGE_BITS - commit_log;
    query.min(commit)
}

/// Queries needed for `bits` of provable soundness from the query phase.
pub fn queries_for(bits: f64) -> usize {
    ((bits - QUERY_POW_BITS as f64) / bits_per_query()).ceil() as usize
}

/// The configuration with `queries` FRI queries, its transcript bound to
/// `statement` (everything the proof is about that is not committed in it).
pub fn config(queries: usize, statement: &[u8; 32]) -> CertStarkConfig {
    let u64_hash = U64Hash::new(KeccakF {});
    let val_mmcs = ValMmcs::new(
        FieldHash::new(u64_hash),
        Compress::new(u64_hash),
        CAP_HEIGHT,
    );
    let fri = FriParameters {
        log_blowup: LOG_BLOWUP,
        log_final_poly_len: 0,
        max_log_arity: 3,
        num_queries: queries,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: QUERY_POW_BITS,
        mmcs: ChallengeMmcs::new(val_mmcs.clone()),
    };
    let pcs = Pcs::new(Dft::default(), val_mmcs, fri);
    let mut seed = TRANSCRIPT_LABEL.to_vec();
    seed.extend_from_slice(statement);
    CertStarkConfig::new(pcs, Challenger::from_hasher(seed, Keccak256Hash {}))
}

/// The Merkle leaf hasher of [`config`].
#[cfg(test)]
pub(crate) fn field_hash() -> FieldHash {
    FieldHash::new(U64Hash::new(KeccakF {}))
}

/// The value that, appended to `input`, leaves its [`U64Hash`] digest
/// unchanged: the sponge overwrites its rate and does not pad, so the cell
/// after a partial final block already holds this value. None when `input`
/// fills its last block, where one more element costs one more permutation.
#[cfg(test)]
pub(crate) fn colliding_extension(input: &[u64]) -> Option<u64> {
    use p3_symmetric::Permutation;
    let partial = input.len() % LEAF_RATE;
    if partial == 0 {
        return None;
    }
    let mut state = [0u64; 25];
    for block in input.as_chunks::<LEAF_RATE>().0 {
        state[..LEAF_RATE].copy_from_slice(block);
        KeccakF {}.permute_mut(&mut state);
    }
    Some(state[partial])
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_keccak_air::{KeccakAir, generate_trace_rows};
    use p3_matrix::Matrix;
    use p3_symmetric::CryptographicHasher;
    use p3_uni_stark::{prove, verify};

    /// The Merkle sponge alone does not separate input lengths: an input and
    /// the same input extended by [`colliding_extension`] hash alike, in the
    /// first block and after it. Proofs stay sound only because the verifier
    /// fixes every leaf's length (compact.rs), and the compression function
    /// always hashes exactly two digests.
    #[test]
    fn the_merkle_sponge_alone_does_not_separate_lengths() {
        let h = U64Hash::new(KeccakF {});
        assert_eq!(h.hash_iter([7u64, 8, 9]), h.hash_iter([7u64, 8, 9, 0]));
        let long: Vec<u64> = (1..=40).collect();
        let e = colliding_extension(&long).expect("40 cells end inside a block");
        let mut longer = long.clone();
        longer.push(e);
        assert_eq!(h.hash_iter(long.iter().copied()), h.hash_iter(longer));
        assert_eq!(colliding_extension(&[0u64; 2 * LEAF_RATE]), None);
    }

    #[test]
    fn a_hundred_bits_holds_in_both_phases_at_the_certificate_domain() {
        let queries = queries_for(100.0);
        assert!(proven_soundness_bits(queries, 24) >= 100.0);
        assert!(proven_soundness_bits(queries - 1, 24) < 100.0);
    }

    /// What proving the SHAKE256 permutations of a quorum's ML-DSA-65
    /// verifications in-circuit would cost on its own (about nine per
    /// signature), under the certificate configuration: the measurement
    /// behind revealing `c~` and `w1` instead. Prints one `COST {json}` line.
    /// Run with `TENZRO_CERT_PERMS=<n>` and `--ignored --nocapture`.
    #[test]
    #[ignore]
    fn cost_of_keccak_permutations() {
        let perms: usize = std::env::var("TENZRO_CERT_PERMS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(603);
        let queries = queries_for(100.0);
        let cfg = config(queries, &[0; 32]);
        let inputs: Vec<[u64; 25]> = (0..perms as u64)
            .map(|i| core::array::from_fn(|j| i * 25 + j as u64))
            .collect();
        let trace = generate_trace_rows::<Val>(inputs, LOG_BLOWUP);
        let rows = trace.height();
        let start = std::time::Instant::now();
        let proof = prove(&cfg, &KeccakAir {}, trace, &[]);
        let prove_ms = start.elapsed().as_secs_f64() * 1e3;
        let start = std::time::Instant::now();
        verify(&cfg, &KeccakAir {}, &proof, &[]).expect("verifies");
        let verify_ms = start.elapsed().as_secs_f64() * 1e3;
        let size = bincode::serialized_size(&proof).expect("proof encodes");
        let log_domain = rows.trailing_zeros() as usize + LOG_BLOWUP;
        println!(
            "COST {{\"what\":\"keccak_permutations\",\"perms\":{perms},\"rows\":{rows},\"queries\":{queries},\
             \"proven_bits\":{:.1},\"prove_ms\":{prove_ms:.0},\"verify_ms\":{verify_ms:.1},\"proof_bytes\":{size}}}",
            proven_soundness_bits(queries, log_domain)
        );
    }
}
