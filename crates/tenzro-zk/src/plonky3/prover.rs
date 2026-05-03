//! Plonky3 STARK prover — wraps `p3_uni_stark::prove`.
//!
//! The prover is generic over the AIR being proved. Each Tenzro circuit
//! (inference / settlement / identity) supplies its own AIR + a function that
//! turns its witness into a [`RowMajorMatrix`] trace plus a `Vec<Val>` of
//! public inputs. The prover then drives the canonical Plonky3 proving
//! pipeline under the pinned [`TenzroStarkConfig`].

use core::marker::PhantomData;

use p3_air::{Air, DebugConstraintBuilder};
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{Proof as P3Proof, SymbolicAirBuilder, prove};

use super::config::{TenzroStarkConfig, Val, build_testnet_config};

/// A STARK prover bound to a specific AIR.
///
/// `A` must implement `p3_air::Air<SymbolicAirBuilder<Val>>` plus the
/// folder builders Plonky3 instantiates internally — this is satisfied by
/// any AIR implementing `Air<AB>` for a generic `AB: AirBuilder<F = Val>`.
pub struct Plonky3Prover<A> {
    config: TenzroStarkConfig,
    _air: PhantomData<A>,
}

impl<A> Default for Plonky3Prover<A> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A> Plonky3Prover<A> {
    /// Construct a prover with the pinned testnet config.
    pub fn new() -> Self {
        Self {
            config: build_testnet_config(),
            _air: PhantomData,
        }
    }

    /// Borrow the underlying [`TenzroStarkConfig`] — exposed so verifiers can
    /// share state if needed.
    pub fn config(&self) -> &TenzroStarkConfig {
        &self.config
    }
}

impl<A> Plonky3Prover<A>
where
    A: Air<SymbolicAirBuilder<Val>>
        + for<'a> Air<p3_uni_stark::ProverConstraintFolder<'a, TenzroStarkConfig>>
        + for<'a> Air<DebugConstraintBuilder<'a, Val>>,
{
    /// Generate a STARK proof for `air` over the given execution `trace` and
    /// `public_values`.
    ///
    /// Trace shape: `[trace_height × air.width()]` row-major. `trace_height`
    /// must be a power of two.
    pub fn prove_air(
        &self,
        air: &A,
        trace: RowMajorMatrix<Val>,
        public_values: &[Val],
    ) -> P3Proof<TenzroStarkConfig> {
        prove(&self.config, air, trace, public_values)
    }
}
