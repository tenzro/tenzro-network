//! Pinned Plonky3 STARK configuration for Tenzro Network.
//!
//! Single canonical config across all circuits — every Tenzro AIR (inference,
//! settlement, identity) proves and verifies under the same field, hash, and
//! FRI parameters. Centralising here means we update soundness/blowup/queries
//! in one place when production hardening lands.
//!
//! # Choices
//!
//! - **Field:** [`KoalaBear`] — 31-bit prime `2^31 - 2^24 + 1`, two-adicity 24,
//!   Poseidon2 round constants tuned for `d=3` exponentiation. KoalaBear is the
//!   2026 Plonky3 default for new STARK deployments (faster than BabyBear when
//!   the field operations dominate, which is our case for the small Tenzro
//!   circuits).
//! - **Extension:** [`BinomialExtensionField<KoalaBear, 4>`] — degree-4
//!   extension lifts security from ~31 bits to ~124 bits, which combined with
//!   the FRI conjectured soundness bound gives us ≥100-bit security.
//! - **Hash / compression:** Poseidon2 over KoalaBear at widths 16
//!   (compression) and 24 (sponge). Constructed via the bundled
//!   `default_koalabear_poseidon2_*` helpers, so no constants need to be
//!   audited locally.
//! - **PCS:** [`TwoAdicFriPcs`] — KoalaBear has two-adicity 24 which is plenty
//!   for any trace height we'll see in Tenzro (≤ 2^20).
//!
//! # FRI parameters
//!
//! `Self::testnet()` returns parameters that prioritise prover speed over
//! proof size — appropriate for a pre-alpha testnet where roundtrip latency
//! matters more than cryptographic margin. `Self::production()` is reserved
//! for mainnet hardening (higher `num_queries`, more PoW bits).

use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::Field;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear, default_koalabear_poseidon2_16, default_koalabear_poseidon2_24};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::StarkConfig;

/// Base field used for all Tenzro circuits.
pub type Val = KoalaBear;

/// Degree-4 extension field — challenges and FRI work in here.
pub type Challenge = BinomialExtensionField<Val, 4>;

/// Poseidon2 permutation at width 16 — used as the Merkle compression function.
pub type Perm16 = Poseidon2KoalaBear<16>;

/// Poseidon2 permutation at width 24 — used as the Fiat-Shamir sponge.
pub type Perm24 = Poseidon2KoalaBear<24>;

/// Sponge hash for leaves: padding-free, rate 8, capacity 8, output 8.
pub type ValHash = PaddingFreeSponge<Perm16, 16, 8, 8>;

/// Two-to-one compression for internal Merkle nodes.
pub type ValCompress = TruncatedPermutation<Perm16, 2, 8, 16>;

/// Mixed Matrix Commitment Scheme over the base field.
pub type ValMmcs = MerkleTreeMmcs<
    <Val as Field>::Packing,
    <Val as Field>::Packing,
    ValHash,
    ValCompress,
    2,
    8,
>;

/// MMCS over the extension field (FRI commits to extension-field polynomials).
pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;

/// Fiat-Shamir transcript using Poseidon2-sponge over the base field.
pub type Challenger = DuplexChallenger<Val, Perm24, 24, 16>;

/// Parallel radix-2 DIT FFT.
pub type Dft = Radix2DitParallel<Val>;

/// FRI-based polynomial commitment scheme — the only PCS we use.
pub type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;

/// Pinned StarkConfig — one type for the whole crate.
pub type TenzroStarkConfig = StarkConfig<Pcs, Challenge, Challenger>;

/// FRI parameters appropriate for Tenzro testnet — fast prover, ~80-bit
/// soundness. See `conjectured_soundness_bits()`: `log_blowup * num_queries +
/// query_proof_of_work_bits` = `1 * 64 + 16` = 80 bits.
fn testnet_fri_parameters(challenge_mmcs: ChallengeMmcs) -> FriParameters<ChallengeMmcs> {
    FriParameters {
        log_blowup: 1,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 64,
        commit_proof_of_work_bits: 8,
        query_proof_of_work_bits: 16,
        mmcs: challenge_mmcs,
    }
}

/// Build a fresh [`TenzroStarkConfig`] with testnet parameters.
///
/// Each call constructs new Poseidon2 permutations from the bundled defaults —
/// no RNG, no seed argument, fully deterministic.
pub fn build_testnet_config() -> TenzroStarkConfig {
    let perm16: Perm16 = default_koalabear_poseidon2_16();
    let perm24: Perm24 = default_koalabear_poseidon2_24();

    let hash = ValHash::new(perm16.clone());
    let compress = ValCompress::new(perm16);
    // cap_height = 0 → tree commits all the way to a single root (no
    // truncation). Our trace heights are small enough that the saving from
    // capping is negligible.
    let val_mmcs = ValMmcs::new(hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    let dft = Dft::default();
    let fri_params = testnet_fri_parameters(challenge_mmcs);
    let pcs = Pcs::new(dft, val_mmcs, fri_params);

    let challenger = Challenger::new(perm24);
    TenzroStarkConfig::new(pcs, challenger)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_builds_deterministically() {
        // Two builds should be structurally identical — Poseidon2 constants are
        // baked into the `default_*` constructors, no RNG involved.
        let _a = build_testnet_config();
        let _b = build_testnet_config();
    }
}
