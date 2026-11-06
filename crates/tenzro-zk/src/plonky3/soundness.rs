//! Proven soundness of the pinned STARK configurations.
//!
//! The number reported is the provable security of the interactive oracle
//! proof made non-interactive in the random-oracle model, with FRI analysed in
//! the Johnson-bound (list-decoding) regime. It does not rely on the
//! up-to-capacity proximity conjecture. The formula follows the ethSTARK
//! analysis and the proximity-gaps theorem for Reed-Solomon codes; the
//! derivation and every input value are written out in
//! `docs/architecture/zk-proof-systems.md`.
//!
//! Notation: `|F|` the challenge-field size, `ρ = 2^-log_blowup` the code
//! rate, `N` the committed trace height, `n = N/ρ` the evaluation domain,
//! `L` the number of committed polynomials batched into FRI, `C` the number
//! of AIR constraints, `d` their maximum degree, `s` the number of FRI queries
//! and `m ≥ 3` the Johnson proximity parameter. With
//! `α = √ρ·(1 + 1/(2m))` and list size `ℓ = (m + 1/2)/√ρ`, the soundness
//! error is bounded by the sum of:
//!
//! - constraint batching: `ℓ·C / |F|`
//! - DEEP out-of-domain sampling: `ℓ·2·(d + 1)·N / |F|`
//! - FRI batching and folding (proximity gaps, curve form):
//!   `(L + log2 n)·(m + 1/2)^7·n^2 / (3·ρ^{3/2}·|F|)`, reduced by
//!   `commit_pow_bits` of grinding
//! - FRI queries: `α^s`, reduced by `query_pow_bits` of grinding
//!
//! The reported bits are `-log2` of that sum, maximised over `m`.

use p3_air::BaseAir;
use p3_air::symbolic::{AirLayout, get_max_constraint_degree, get_symbolic_constraints};

use crate::circuits::Circuit;
use crate::circuits::preimage::{NUM_PUBLIC_VALUES, PreimageAir, TRACE_HEIGHT};

/// Field and FRI parameters of one proof system.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SystemParameters {
    /// `log2` of the base-field order.
    pub base_field_bits: f64,
    /// Degree of the challenge extension field.
    pub extension_degree: u32,
    /// `log2(1/ρ)`.
    pub log_blowup: usize,
    /// FRI query repetitions.
    pub num_queries: usize,
    /// Proof-of-work bits ground before query sampling.
    pub query_pow_bits: usize,
    /// Proof-of-work bits ground before each folding challenge.
    pub commit_pow_bits: usize,
}

/// Size and degree of the AIR being proven.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AirShape {
    /// `log2` of the committed trace height (after hiding randomization).
    pub log_trace_height: usize,
    /// Polynomials batched into FRI (main columns, quotient chunks,
    /// randomizer columns), as an upper bound.
    pub num_polynomials: usize,
    /// AIR constraints.
    pub num_constraints: usize,
    /// Maximum constraint degree.
    pub max_degree: usize,
}

/// Security of one parameter set, in bits.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SoundnessReport {
    /// Proven security: `-log2` of the total soundness error.
    pub proven_bits: f64,
    /// Contribution of the FRI query phase alone.
    pub query_bits: f64,
    /// Contribution of FRI batching and folding alone.
    pub commit_bits: f64,
    /// Contribution of constraint batching alone.
    pub constraint_bits: f64,
    /// Contribution of DEEP sampling alone.
    pub deep_bits: f64,
    /// The Johnson proximity parameter that maximised `proven_bits`.
    pub proximity_m: usize,
    /// Security under the up-to-capacity conjecture, for comparison only:
    /// `log_blowup · s + query_pow_bits`.
    pub conjectured_bits: f64,
}

/// Compute the proven security of `params` for an AIR of shape `shape`.
pub fn proven_security(params: &SystemParameters, shape: &AirShape) -> SoundnessReport {
    let field_bits = params.base_field_bits * f64::from(params.extension_degree);
    let log_rho = -(params.log_blowup as f64);
    let log_sqrt_rho = log_rho / 2.0;
    let log_n = (shape.log_trace_height + params.log_blowup) as f64;
    let log_trace = shape.log_trace_height as f64;

    let mut best: Option<SoundnessReport> = None;
    for m in 3..=4096usize {
        let m_f = m as f64;
        let log_alpha = log_sqrt_rho + (1.0 + 1.0 / (2.0 * m_f)).log2();
        let log_list = (m_f + 0.5).log2() - log_sqrt_rho;

        let query_bits = -(params.num_queries as f64) * log_alpha + params.query_pow_bits as f64;
        let constraint_bits = field_bits - log_list - (shape.num_constraints as f64).log2();
        let deep_bits =
            field_bits - log_list - (2.0 * (shape.max_degree as f64 + 1.0)).log2() - log_trace;
        let log_commit_error = 7.0 * (m_f + 0.5).log2() - 3f64.log2() - 1.5 * log_rho
            + 2.0 * log_n
            + (shape.num_polynomials as f64 + log_n).log2()
            - field_bits;
        let commit_bits = -log_commit_error + params.commit_pow_bits as f64;

        let total_error = [query_bits, constraint_bits, deep_bits, commit_bits]
            .iter()
            .map(|b| (-b).exp2())
            .sum::<f64>();
        let proven_bits = -total_error.log2();

        if best.is_none_or(|b| proven_bits > b.proven_bits) {
            best = Some(SoundnessReport {
                proven_bits,
                query_bits,
                commit_bits,
                constraint_bits,
                deep_bits,
                proximity_m: m,
                conjectured_bits: (params.log_blowup * params.num_queries + params.query_pow_bits)
                    as f64,
            });
        }
    }
    best.expect("the proximity range is non-empty")
}

/// Shape of the preimage AIR as committed by the hiding PCS: the trace is
/// doubled by randomization, and the batch carries the main columns, the
/// randomizer columns and the quotient chunks (bounded here by 64 extra
/// polynomials).
pub fn preimage_air_shape() -> AirShape {
    let air = PreimageAir::new(Circuit::Settlement);
    let layout = AirLayout {
        main_width: <PreimageAir as BaseAir<p3_koala_bear::KoalaBear>>::width(&air),
        num_public_values: NUM_PUBLIC_VALUES,
        ..Default::default()
    };
    let constraints = get_symbolic_constraints::<p3_koala_bear::KoalaBear, _>(&air, layout);
    let max_degree = get_max_constraint_degree::<p3_koala_bear::KoalaBear, _>(&air, layout);
    AirShape {
        log_trace_height: TRACE_HEIGHT.trailing_zeros() as usize + 1,
        num_polynomials: layout.main_width + 64,
        num_constraints: constraints.len(),
        max_degree,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plonky3::config::{goldilocks, koala_bear};

    #[test]
    fn koala_bear_system_reaches_128_proven_bits() {
        let shape = preimage_air_shape();
        let r = proven_security(&koala_bear::PARAMETERS, &shape);
        eprintln!("{shape:?}\n{r:?}");
        assert!(r.proven_bits >= 128.0, "{r:?}");
    }

    #[test]
    fn goldilocks_system_reaches_128_proven_bits() {
        let r = proven_security(&goldilocks::PARAMETERS, &preimage_air_shape());
        eprintln!("{r:?}");
        assert!(r.proven_bits >= 128.0, "{r:?}");
    }

    /// The previous configuration (rate 1/2, 64 queries, 16 PoW bits,
    /// degree-4 KoalaBear extension) evaluated with the same formula comes
    /// out near 48 proven bits. If this ever reports 100 the formula has been
    /// loosened, not the configuration strengthened.
    #[test]
    fn rate_one_half_with_64_queries_is_far_below_100_bits() {
        let weak = SystemParameters {
            base_field_bits: 30.988_684,
            extension_degree: 4,
            log_blowup: 1,
            num_queries: 64,
            query_pow_bits: 16,
            commit_pow_bits: 8,
        };
        let r = proven_security(&weak, &preimage_air_shape());
        eprintln!("{r:?}");
        assert!(r.proven_bits < 50.0, "{r:?}");
        assert!(r.proven_bits > 40.0, "{r:?}");
        assert_eq!(r.conjectured_bits, 80.0);
    }

    #[test]
    fn preimage_air_shape_is_what_the_formula_assumes() {
        let shape = preimage_air_shape();
        // Keccak-f constraints are degree 3; the first-permutation selector
        // multiplies the output constraints by one more degree.
        assert!(shape.max_degree <= 4, "{shape:?}");
        assert!(shape.num_constraints > 1000, "{shape:?}");
        assert_eq!(shape.log_trace_height, 8);
    }

    /// The hiding PCS keeps the witness hidden only while the verifier opens
    /// fewer points than there are random rows mixed into the trace.
    #[test]
    fn opened_points_stay_below_the_randomized_rows() {
        for p in [koala_bear::PARAMETERS, goldilocks::PARAMETERS] {
            assert!(p.num_queries + 2 <= TRACE_HEIGHT, "{p:?}");
        }
    }
}
